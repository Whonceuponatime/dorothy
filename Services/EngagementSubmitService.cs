using System;
using System.Collections.Generic;
using System.Net;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Dorothy.Models;
using Dorothy.Models.Database;
using NLog;

namespace Dorothy.Services
{
    public sealed class SubmitResult
    {
        public bool Success { get; set; }
        public string? ErrorMessage { get; set; }
        public int? StatusCode { get; set; }
        public string? RemoteId { get; set; }
    }

    /// <summary>
    /// Bundles a local engagement (assets / ports / attack runs / topology
    /// snapshot) and posts it to /api/engagements as a single transaction.
    /// Replaces the old SupabaseSyncService per-row sync flow.
    /// </summary>
    public sealed class EngagementSubmitService
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();

        private readonly DatabaseService _db;
        private readonly string _hardwareId;

        public EngagementSubmitService(DatabaseService db, string hardwareId)
        {
            _db = db;
            _hardwareId = hardwareId;
        }

        /// <summary>
        /// Bundle the current session's unsubmitted scan rows into a new
        /// engagement, POST to SEACUREDB, and on success: INSERT the engagement
        /// row locally + flip EngagementId on every session row.
        /// </summary>
        public async Task<SubmitResult> SubmitAsync(
            string name,
            string? clientName,
            string? scope,
            string? notes,
            string? surveyorEmail,
            DateTime sessionStartedAt,
            bool clearAfterSubmit,
            TopologyGraph? topology,
            IProgress<string>? progress,
            CancellationToken ct)
        {
            // 30-second hard ceiling on the whole submit. Inside the ceiling,
            // each HTTP leg has its own 15s LicenseApiClient timeout.
            using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, timeoutCts.Token);
            try
            {
                return await SubmitInternalAsync(
                    name, clientName, scope, notes, surveyorEmail,
                    sessionStartedAt, clearAfterSubmit, topology, progress,
                    linkedCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested && !ct.IsCancellationRequested)
            {
                Logger.Warn("[ENGAGEMENT-SUBMIT] Overall 30s timeout hit");
                return new SubmitResult
                {
                    Success = false,
                    ErrorMessage = "Submit timed out after 30 seconds. Check internet connectivity and try again."
                };
            }
        }

        private async Task<SubmitResult> SubmitInternalAsync(
            string name,
            string? clientName,
            string? scope,
            string? notes,
            string? surveyorEmail,
            DateTime sessionStartedAt,
            bool clearAfterSubmit,
            TopologyGraph? topology,
            IProgress<string>? progress,
            CancellationToken ct)
        {
            try
            {
                progress?.Report("Building payload...");
                var assets = await _db.GetUnsubmittedAssetsAsync();
                var ports = await _db.GetUnsubmittedPortsAsync();
                var attackRuns = await _db.GetUnsubmittedAttackLogsAsync();
                var topoNodeCount = await _db.CountUnsubmittedTopologyNodesAsync();

                if (assets.Count == 0 && attackRuns.Count == 0 && topoNodeCount == 0)
                {
                    return new SubmitResult
                    {
                        Success = false,
                        ErrorMessage = "Nothing to submit — no unsubmitted scan or attack activity."
                    };
                }

                var transientEngagement = new Engagement
                {
                    Name = name,
                    ClientName = clientName,
                    Scope = scope,
                    Notes = notes,
                    StartedAt = sessionStartedAt,
                    EndedAt = DateTime.UtcNow,
                    Status = EngagementStatus.Submitted,
                    SurveyorHardwareId = _hardwareId,
                    SurveyorEmail = surveyorEmail,
                    CreatedAt = DateTime.UtcNow,
                    SubmittedAt = DateTime.UtcNow
                };

                var payload = BuildPayload(transientEngagement, assets, ports, attackRuns, topology);

                // No auth step — surveyor identity is asserted via the
                // surveyor_hardware_id field in the body, validated against
                // whitelisted_hardware on the server. License validation
                // already happened at app startup via RSA-signed response;
                // re-authing here was overengineered for a single-user system
                // and was the cause of the "Authenticating…" hang.
                progress?.Report("Uploading to SEACUREDB...");
                Logger.Info($"[ENGAGEMENT-SUBMIT] POST {SeacureConfig.ApiUrl}/api/engagements");

                using var client = new LicenseApiClient(SeacureConfig.ApiUrl);
                var json = JsonSerializer.Serialize(payload);
                System.Net.Http.HttpResponseMessage resp;
                string body;
                try
                {
                    resp = await client.PostEngagementAsync(json, ct).ConfigureAwait(false);
                    body = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                }
                catch (TaskCanceledException) when (ct.IsCancellationRequested)
                {
                    throw;
                }
                catch (TaskCanceledException)
                {
                    Logger.Warn("[ENGAGEMENT-SUBMIT] Upload timed out (15s per-request)");
                    return new SubmitResult
                    {
                        Success = false,
                        ErrorMessage = "Upload timed out. Try again."
                    };
                }
                catch (System.Net.Http.HttpRequestException ex)
                {
                    Logger.Warn(ex, "[ENGAGEMENT-SUBMIT] Network error during POST");
                    return new SubmitResult
                    {
                        Success = false,
                        ErrorMessage = $"Network error: {ex.Message}"
                    };
                }
                using var _resp = resp;

                if (!resp.IsSuccessStatusCode)
                {
                    var msg = MapStatusToMessage((int)resp.StatusCode, body);
                    Logger.Warn($"[ENGAGEMENT-SUBMIT] Server returned {(int)resp.StatusCode}: {body}");
                    return new SubmitResult
                    {
                        Success = false,
                        StatusCode = (int)resp.StatusCode,
                        ErrorMessage = msg
                    };
                }

                progress?.Report("Marking submitted locally...");
                string? remoteId = null;
                try
                {
                    using var doc = JsonDocument.Parse(body);
                    if (doc.RootElement.TryGetProperty("id", out var idEl))
                        remoteId = idEl.GetString();
                }
                catch (Exception ex) { Logger.Warn(ex, "[ENGAGEMENT-SUBMIT] Could not parse server response id"); }

                transientEngagement.RemoteId = remoteId;
                var localEngagementId = await _db.InsertEngagementAsync(transientEngagement).ConfigureAwait(false);

                int rows;
                if (clearAfterSubmit)
                {
                    progress?.Report("Clearing local copy of submitted data...");
                    rows = await _db.DeleteAllUnsubmittedAsync().ConfigureAwait(false);
                    Logger.Info($"[ENGAGEMENT-SUBMIT] local={localEngagementId} remote={remoteId} hardDeletedRows={rows}");
                }
                else
                {
                    progress?.Report("Tagging local rows with engagement id...");
                    rows = await _db.AssignEngagementIdToUnsubmittedAsync(localEngagementId).ConfigureAwait(false);
                    Logger.Info($"[ENGAGEMENT-SUBMIT] local={localEngagementId} remote={remoteId} taggedRows={rows}");
                }

                EngagementContext.NotifyActivityChanged();

                return new SubmitResult { Success = true, RemoteId = remoteId };
            }
            catch (TaskCanceledException)
            {
                return new SubmitResult
                {
                    Success = false,
                    ErrorMessage = "Connection issue — could not reach the server. Try again."
                };
            }
            catch (System.Net.Http.HttpRequestException ex)
            {
                Logger.Warn(ex, "[ENGAGEMENT-SUBMIT] Network error");
                return new SubmitResult
                {
                    Success = false,
                    ErrorMessage = $"Network error: {ex.Message}"
                };
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "[ENGAGEMENT-SUBMIT] Unexpected failure");
                return new SubmitResult
                {
                    Success = false,
                    ErrorMessage = $"Unexpected error: {ex.Message}"
                };
            }
        }

        private static string MapStatusToMessage(int status, string body)
        {
            return status switch
            {
                400 => $"Invalid payload: {Truncate(body, 200)}",
                403 => "This device is not approved for SEACUREDB. Check your license status.",
                409 => "This engagement was already submitted. Refresh local state.",
                413 => "Payload too large. Contact support.",
                422 => $"Server rejected the engagement: {Truncate(body, 200)}",
                >= 500 and < 600 => "Server error. Try again later.",
                _ => $"Server returned {status}: {Truncate(body, 200)}"
            };
        }

        private static string Truncate(string s, int max)
            => string.IsNullOrEmpty(s) ? string.Empty
               : (s.Length <= max ? s : s.Substring(0, max) + "…");

        private object BuildPayload(
            Engagement engagement,
            List<AssetEntry> assets,
            List<PortEntry> ports,
            List<AttackLogEntry> attackRuns,
            TopologyGraph? topology)
        {
            // Group ports by host_ip so each asset embeds its own port array
            // (matches §8 of the redesign plan).
            var portsByHost = new Dictionary<string, List<PortEntry>>(StringComparer.OrdinalIgnoreCase);
            foreach (var p in ports)
            {
                if (!portsByHost.TryGetValue(p.HostIp, out var list))
                {
                    list = new List<PortEntry>();
                    portsByHost[p.HostIp] = list;
                }
                list.Add(p);
            }

            var assetPayloads = new List<object>(assets.Count);
            foreach (var a in assets)
            {
                portsByHost.TryGetValue(a.HostIp, out var assetPorts);
                var portPayloads = (assetPorts ?? new List<PortEntry>()).ConvertAll<object>(p => new
                {
                    port = p.Port,
                    protocol = p.Protocol,
                    service = p.Service,
                    banner = p.Banner,
                    severity = (string?)null,
                    scan_time = p.ScanTime
                });

                object? industrialIdentity = null;
                if (!string.IsNullOrWhiteSpace(a.IndustrialVendor)
                    || !string.IsNullOrWhiteSpace(a.IndustrialCategory)
                    || !string.IsNullOrWhiteSpace(a.IndustrialProtocols))
                {
                    string[] protocols = string.IsNullOrWhiteSpace(a.IndustrialProtocols)
                        ? Array.Empty<string>()
                        : a.IndustrialProtocols.Split(',', StringSplitOptions.RemoveEmptyEntries
                            | StringSplitOptions.TrimEntries);
                    industrialIdentity = new
                    {
                        vendor = a.IndustrialVendor,
                        category = a.IndustrialCategory,
                        industrial_protocols = protocols
                    };
                }

                assetPayloads.Add(new
                {
                    host_ip = a.HostIp,
                    host_name = a.HostName,
                    mac_address = a.MacAddress,
                    vendor = a.Vendor,
                    is_online = a.IsOnline,
                    scan_time = a.ScanTime,
                    ports = portPayloads,
                    industrial_identity = industrialIdentity
                });
            }

            var attackPayloads = new List<object>(attackRuns.Count);
            foreach (var r in attackRuns)
            {
                attackPayloads.Add(new
                {
                    attack_type = r.AttackType,
                    protocol = r.Protocol,
                    target_ip = r.TargetIp,
                    target_port = r.TargetPort,
                    target_rate_mbps = r.TargetRateMbps,
                    packets_sent = r.PacketsSent,
                    duration_seconds = r.DurationSeconds,
                    start_time = r.StartTime,
                    stop_time = r.StopTime
                });
            }

            object? topologyPayload = null;
            if (topology != null)
            {
                try
                {
                    // Reuse the existing Cytoscape-shaped serializer; server stores
                    // verbatim in topology_snapshot JSONB.
                    var cyJson = topology.ToCytoscapeJson();
                    using var doc = JsonDocument.Parse(cyJson);
                    topologyPayload = doc.RootElement.Clone();
                }
                catch (Exception ex)
                {
                    Logger.Warn(ex, "[ENGAGEMENT-SUBMIT] Topology snapshot failed; submitting without topology.");
                }
            }

            return new
            {
                name = engagement.Name,
                client_name = engagement.ClientName,
                scope = engagement.Scope,
                started_at = engagement.StartedAt,
                ended_at = engagement.EndedAt ?? DateTime.UtcNow,
                surveyor_hardware_id = engagement.SurveyorHardwareId,
                surveyor_email = engagement.SurveyorEmail,
                notes = engagement.Notes,
                assets = assetPayloads,
                attack_runs = attackPayloads,
                topology = topologyPayload
            };
        }
    }
}
