using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using Dorothy.Models;
using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;
using NLog;

namespace Dorothy.Services
{
    public class ReachabilityProbeService
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();

        private static readonly (string Oid, string Name)[] SnmpOids = new[]
        {
            ("1.3.6.1.2.1.1.1.0", "sysDescr"),
            ("1.3.6.1.2.1.1.5.0", "sysName"),
            ("1.3.6.1.2.1.1.3.0", "sysUpTime"),
            ("1.3.6.1.2.1.1.6.0", "sysLocation"),
            ("1.3.6.1.2.1.1.4.0", "sysContact")
        };

        private const int HostConcurrency = 20;
        private const int TcpScanConcurrency = 10;
        private const int IcmpPingAttempts = 3;
        private const int IcmpPingTimeoutMs = 1000;
        private const int TracerouteMaxHops = 30;
        private const int TracerouteTimeoutMs = 500;
        private const int TracerouteConsecutiveNoReplyStop = 3;
        private const int TcpConnectTimeoutMs = 2000;
        private const int SnmpTimeoutMs = 2000;
        private const int SnmpPort = 161;
        private const int HostCap = 1024;

        private readonly DatabaseService _database;

        private CancellationTokenSource? _cts;
        private int _isRunning;

        public bool IsRunning => Volatile.Read(ref _isRunning) == 1;

        /// <summary>
        /// When true, ICMP ping uses 1 attempt instead of 3. Set by the
        /// orchestrator before calling StartRunAsync when the user has the
        /// NI stealth toggle on.
        /// </summary>
        public bool StealthMode { get; set; }

        public ReachabilityProbeService(DatabaseService database)
        {
            _database = database ?? throw new ArgumentNullException(nameof(database));
        }

        public void Cancel()
        {
            try { _cts?.Cancel(); } catch { }
        }

        public async Task<long> StartRunAsync(
            ProbeTarget target,
            string? sourceIp,
            string? sourceNic,
            string? runLabel,
            Action<HostProbeResult>? onHostUpdated,
            Action<ReachabilityRun>? onRunCompleted,
            CancellationToken cancellationToken)
        {
            if (target == null) throw new ArgumentNullException(nameof(target));

            if (Interlocked.CompareExchange(ref _isRunning, 1, 0) != 0)
            {
                throw new InvalidOperationException("A reachability run is already in progress.");
            }

            _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            var token = _cts.Token;

            var run = new ReachabilityRun
            {
                StartedAt = DateTime.UtcNow,
                Label = string.IsNullOrWhiteSpace(runLabel) ? null : runLabel.Trim(),
                SourceIp = sourceIp,
                SourceNic = sourceNic,
                TargetRaw = target.Raw
            };

            try
            {
                run.Id = await _database.SaveReachabilityRunAsync(run).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Failed to persist initial reachability run record");
            }

            List<string> ips;
            try
            {
                ips = target.ExpandedIps != null && target.ExpandedIps.Count > 0
                    ? target.ExpandedIps
                    : TargetIpExpander.Expand(target.Raw ?? string.Empty, HostCap);
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Target expansion failed");
                ips = new List<string>();
            }

            if (ips.Count == 0)
            {
                var errorHost = new HostProbeResult
                {
                    IpAddress = target.Raw ?? string.Empty,
                    Status = ProbeStatus.Error,
                    Summary = "Could not parse any IPv4 targets from the input.",
                    StartedAt = DateTime.UtcNow,
                    CompletedAt = DateTime.UtcNow
                };
                PublishHost(onHostUpdated, errorHost);

                run.HostsTested = 0;
                run.CompletedAt = DateTime.UtcNow;
                run.ResultsJson = SafeSerialize(new[] { errorHost });
                await PersistFinalAsync(run).ConfigureAwait(false);
                PublishRun(onRunCompleted, run);
                ResetState();
                return run.Id;
            }

            if (ips.Count > HostCap)
            {
                var errorHost = new HostProbeResult
                {
                    IpAddress = target.Raw ?? string.Empty,
                    Status = ProbeStatus.Error,
                    Summary = $"Target expands to {ips.Count} hosts which exceeds the {HostCap} host cap.",
                    StartedAt = DateTime.UtcNow,
                    CompletedAt = DateTime.UtcNow
                };
                PublishHost(onHostUpdated, errorHost);

                run.HostsTested = 0;
                run.CompletedAt = DateTime.UtcNow;
                run.ResultsJson = SafeSerialize(new[] { errorHost });
                await PersistFinalAsync(run).ConfigureAwait(false);
                PublishRun(onRunCompleted, run);
                ResetState();
                return run.Id;
            }

            var results = new List<HostProbeResult>(ips.Count);
            foreach (var ip in ips)
            {
                results.Add(new HostProbeResult
                {
                    IpAddress = ip,
                    Status = ProbeStatus.Pending,
                    StartedAt = DateTime.UtcNow
                });
            }

            foreach (var host in results)
            {
                PublishHost(onHostUpdated, host);
            }

            var parallelism = Math.Max(1, Math.Min(results.Count, HostConcurrency));
            using var hostGate = new SemaphoreSlim(parallelism, parallelism);
            var tasks = new List<Task>(results.Count);

            foreach (var host in results)
            {
                tasks.Add(ProbeHostWithGateAsync(host, target, sourceIp, hostGate, onHostUpdated, token));
            }

            try
            {
                await Task.WhenAll(tasks).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Reachability run encountered an unhandled fault");
            }

            run.HostsTested = results.Count;
            run.HostsReachable = results.Count(r => r.Status == ProbeStatus.Reachable);
            run.HostsPartial = results.Count(r => r.Status == ProbeStatus.Partial);
            run.HostsUnreachable = results.Count(r => r.Status == ProbeStatus.Unreachable);
            run.HostsNoRoute = results.Count(r => r.Status == ProbeStatus.NoRoute);
            run.CompletedAt = DateTime.UtcNow;
            run.ResultsJson = SafeSerialize(results);

            await PersistFinalAsync(run).ConfigureAwait(false);
            PublishRun(onRunCompleted, run);

            ResetState();
            return run.Id;
        }

        private async Task ProbeHostWithGateAsync(
            HostProbeResult host,
            ProbeTarget target,
            string? sourceIp,
            SemaphoreSlim gate,
            Action<HostProbeResult>? onHostUpdated,
            CancellationToken token)
        {
            await gate.WaitAsync(token).ConfigureAwait(false);
            try
            {
                await ProbeHostAsync(host, target, sourceIp, onHostUpdated, token).ConfigureAwait(false);
            }
            finally
            {
                gate.Release();
            }
        }

        private async Task ProbeHostAsync(
            HostProbeResult host,
            ProbeTarget target,
            string? sourceIp,
            Action<HostProbeResult>? onHostUpdated,
            CancellationToken token)
        {
            host.Status = ProbeStatus.Running;
            host.StartedAt = DateTime.UtcNow;
            PublishHost(onHostUpdated, host);

            try
            {
                if (target.RunRouteCheck)
                {
                    var route = TargetIpExpander.DetermineRoute(host.IpAddress, sourceIp ?? string.Empty);
                    host.RouteStatus = route.status;
                    host.RouteGateway = route.gateway;
                    PublishHost(onHostUpdated, host);

                    if (route.status == RouteStatus.NoRoute)
                    {
                        host.Status = ProbeStatus.NoRoute;
                        host.Summary = "No route to host — no matching interface or default gateway.";
                        host.CompletedAt = DateTime.UtcNow;
                        PublishHost(onHostUpdated, host);
                        return;
                    }
                }

                try
                {
                    var entry = await Dns.GetHostEntryAsync(host.IpAddress).ConfigureAwait(false);
                    if (!string.IsNullOrWhiteSpace(entry.HostName) && !string.Equals(entry.HostName, host.IpAddress, StringComparison.Ordinal))
                    {
                        host.Hostname = entry.HostName;
                        PublishHost(onHostUpdated, host);
                    }
                }
                catch { }

                if (token.IsCancellationRequested) return;

                if (target.RunIcmpPing)
                {
                    await RunIcmpPingAsync(host, token).ConfigureAwait(false);
                    PublishHost(onHostUpdated, host);
                }

                if (token.IsCancellationRequested) return;

                if (target.RunTraceroute)
                {
                    await RunIcmpTracerouteAsync(host, token).ConfigureAwait(false);
                    PublishHost(onHostUpdated, host);
                }

                if (token.IsCancellationRequested) return;

                if (target.RunTcpTraceroute)
                {
                    await RunTcpTracerouteAsync(host, target, token).ConfigureAwait(false);
                    PublishHost(onHostUpdated, host);
                }

                if (token.IsCancellationRequested) return;

                if (target.RunTcpScan && target.TcpPorts != null && target.TcpPorts.Count > 0)
                {
                    await RunTcpScanAsync(host, target.TcpPorts, token).ConfigureAwait(false);
                    PublishHost(onHostUpdated, host);
                }

                if (token.IsCancellationRequested) return;

                bool snmpResponded = false;
                if (target.RunSnmpProbe)
                {
                    snmpResponded = await RunSnmpProbeAsync(host, target.SnmpCommunity ?? "public", token).ConfigureAwait(false);
                    PublishHost(onHostUpdated, host);
                }

                host.Status = ResolveStatus(host, target, snmpResponded);
                host.Summary = BuildSummary(host, target, snmpResponded);
            }
            catch (OperationCanceledException)
            {
                host.Status = ProbeStatus.Error;
                host.Summary = "Probe cancelled.";
            }
            catch (Exception ex)
            {
                Logger.Error(ex, $"Probe failed for {host.IpAddress}");
                host.Status = ProbeStatus.Error;
                host.Summary = $"Probe error: {ex.Message}";
            }
            finally
            {
                host.CompletedAt = DateTime.UtcNow;
                PublishHost(onHostUpdated, host);
            }
        }

        private async Task RunIcmpPingAsync(HostProbeResult host, CancellationToken token)
        {
            long? bestRtt = null;
            bool anyReply = false;
            bool anyError = false;

            using var ping = new Ping();
            int attempts = StealthMode ? 1 : IcmpPingAttempts;
            for (int i = 0; i < attempts; i++)
            {
                if (token.IsCancellationRequested) break;
                try
                {
                    var reply = await ping.SendPingAsync(host.IpAddress, IcmpPingTimeoutMs).ConfigureAwait(false);
                    if (reply.Status == IPStatus.Success)
                    {
                        anyReply = true;
                        var rtt = reply.RoundtripTime;
                        if (!bestRtt.HasValue || rtt < bestRtt.Value) bestRtt = rtt;
                    }
                }
                catch (PingException)
                {
                    anyError = true;
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch
                {
                    anyError = true;
                }
            }

            if (anyReply)
            {
                host.IcmpStatus = IcmpStatus.Reply;
                host.IcmpRttMs = bestRtt;
            }
            else if (anyError)
            {
                host.IcmpStatus = IcmpStatus.Error;
            }
            else
            {
                host.IcmpStatus = IcmpStatus.NoReply;
            }
        }

        private async Task RunIcmpTracerouteAsync(HostProbeResult host, CancellationToken token)
        {
            host.TracerouteHops.Clear();
            var buffer = new byte[32];
            int consecutiveNoReply = 0;

            using var ping = new Ping();
            for (int ttl = 1; ttl <= TracerouteMaxHops; ttl++)
            {
                if (token.IsCancellationRequested) break;
                var options = new PingOptions(ttl, true);
                var hop = new TracerouteHop { HopNumber = ttl };

                try
                {
                    var reply = await ping.SendPingAsync(host.IpAddress, TracerouteTimeoutMs, buffer, options).ConfigureAwait(false);
                    if (reply.Status == IPStatus.Success || reply.Status == IPStatus.TtlExpired)
                    {
                        hop.IpAddress = reply.Address?.ToString();
                        hop.RttMs = reply.RoundtripTime;
                        hop.NoReply = false;
                        consecutiveNoReply = 0;

                        host.TracerouteHops.Add(hop);
                        if (reply.Status == IPStatus.Success) break;
                    }
                    else
                    {
                        hop.NoReply = true;
                        consecutiveNoReply++;
                        host.TracerouteHops.Add(hop);
                        if (consecutiveNoReply >= TracerouteConsecutiveNoReplyStop) break;
                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch
                {
                    hop.NoReply = true;
                    consecutiveNoReply++;
                    host.TracerouteHops.Add(hop);
                    if (consecutiveNoReply >= TracerouteConsecutiveNoReplyStop) break;
                }
            }
        }

        private async Task RunTcpTracerouteAsync(HostProbeResult host, ProbeTarget target, CancellationToken token)
        {
            host.TcpTracerouteHops.Clear();

            int port = target.TcpPorts != null && target.TcpPorts.Count > 0 ? target.TcpPorts[0] : 443;
            var noteHop = new TracerouteHop
            {
                HopNumber = 0,
                NoReply = false,
                IpAddress = host.IpAddress,
                Hostname = $"TCP traceroute to port {port}: Windows raw-socket TCP traceroute not supported; using ICMP TTL probe as fallback.",
                RttMs = null
            };
            host.TcpTracerouteHops.Add(noteHop);

            var buffer = new byte[32];
            int consecutiveNoReply = 0;

            using var ping = new Ping();
            for (int ttl = 1; ttl <= TracerouteMaxHops; ttl++)
            {
                if (token.IsCancellationRequested) break;
                var options = new PingOptions(ttl, true);
                var hop = new TracerouteHop { HopNumber = ttl };

                try
                {
                    var reply = await ping.SendPingAsync(host.IpAddress, TracerouteTimeoutMs, buffer, options).ConfigureAwait(false);
                    if (reply.Status == IPStatus.Success || reply.Status == IPStatus.TtlExpired)
                    {
                        hop.IpAddress = reply.Address?.ToString();
                        hop.RttMs = reply.RoundtripTime;
                        hop.NoReply = false;
                        consecutiveNoReply = 0;
                        host.TcpTracerouteHops.Add(hop);
                        if (reply.Status == IPStatus.Success) break;
                    }
                    else
                    {
                        hop.NoReply = true;
                        consecutiveNoReply++;
                        host.TcpTracerouteHops.Add(hop);
                        if (consecutiveNoReply >= TracerouteConsecutiveNoReplyStop) break;
                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch
                {
                    hop.NoReply = true;
                    consecutiveNoReply++;
                    host.TcpTracerouteHops.Add(hop);
                    if (consecutiveNoReply >= TracerouteConsecutiveNoReplyStop) break;
                }
            }
        }

        private async Task RunTcpScanAsync(HostProbeResult host, List<int> ports, CancellationToken token)
        {
            host.TcpPorts.Clear();
            foreach (var p in ports) host.TcpPorts[p] = PortStatus.Filtered;

            var parallelism = Math.Max(1, Math.Min(ports.Count, TcpScanConcurrency));
            using var gate = new SemaphoreSlim(parallelism, parallelism);
            var tasks = new List<Task>(ports.Count);

            foreach (var port in ports.Distinct())
            {
                tasks.Add(ProbeTcpPortAsync(host, port, gate, token));
            }

            try
            {
                await Task.WhenAll(tasks).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
        }

        private async Task ProbeTcpPortAsync(HostProbeResult host, int port, SemaphoreSlim gate, CancellationToken token)
        {
            await gate.WaitAsync(token).ConfigureAwait(false);
            try
            {
                using var client = new TcpClient();
                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(token);
                timeoutCts.CancelAfter(TcpConnectTimeoutMs);

                try
                {
                    await client.ConnectAsync(host.IpAddress, port, timeoutCts.Token).ConfigureAwait(false);
                    host.TcpPorts[port] = PortStatus.Open;
                }
                catch (OperationCanceledException) when (!token.IsCancellationRequested)
                {
                    host.TcpPorts[port] = PortStatus.Filtered;
                }
                catch (SocketException se)
                {
                    host.TcpPorts[port] = se.SocketErrorCode switch
                    {
                        SocketError.ConnectionRefused => PortStatus.Closed,
                        SocketError.TimedOut => PortStatus.Filtered,
                        SocketError.HostUnreachable => PortStatus.Filtered,
                        SocketError.NetworkUnreachable => PortStatus.Filtered,
                        _ => PortStatus.Error
                    };
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch
                {
                    host.TcpPorts[port] = PortStatus.Error;
                }
            }
            finally
            {
                gate.Release();
            }
        }

        private Task<bool> RunSnmpProbeAsync(HostProbeResult host, string community, CancellationToken token)
        {
            return Task.Run(() =>
            {
                bool responded = false;
                try
                {
                    if (!IPAddress.TryParse(host.IpAddress, out var ip)) return false;
                    var endpoint = new IPEndPoint(ip, SnmpPort);
                    var communityObject = new OctetString(community);

                    foreach (var (oid, name) in SnmpOids)
                    {
                        if (token.IsCancellationRequested) break;
                        try
                        {
                            var variables = new List<Variable> { new Variable(new ObjectIdentifier(oid)) };
                            var reply = Messenger.Get(
                                VersionCode.V2,
                                endpoint,
                                communityObject,
                                variables,
                                SnmpTimeoutMs);

                            if (reply != null && reply.Count > 0)
                            {
                                var value = reply[0].Data?.ToString() ?? string.Empty;
                                host.SnmpValues[name] = value;
                                responded = true;
                            }
                        }
                        catch (Lextm.SharpSnmpLib.Messaging.TimeoutException)
                        {
                        }
                        catch (SocketException)
                        {
                        }
                        catch (Exception ex)
                        {
                            Logger.Debug(ex, $"SNMP GET failed for {host.IpAddress} {oid}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    Logger.Debug(ex, $"SNMP probe failed for {host.IpAddress}");
                }
                return responded;
            }, token);
        }

        private static ProbeStatus ResolveStatus(HostProbeResult host, ProbeTarget target, bool snmpResponded)
        {
            if (target.RunRouteCheck && host.RouteStatus == RouteStatus.NoRoute)
            {
                return ProbeStatus.NoRoute;
            }

            bool icmpOk = host.IcmpStatus == IcmpStatus.Reply;
            bool tcpScanned = host.TcpPorts.Count > 0;
            bool anyTcpOpen = host.TcpPorts.Values.Any(v => v == PortStatus.Open);
            bool anyTcpClosed = host.TcpPorts.Values.Any(v => v == PortStatus.Closed);
            bool anyTcpFiltered = host.TcpPorts.Values.Any(v => v == PortStatus.Filtered);

            // Strong evidence the host is actually present at the network layer.
            // Closed counts here: a TCP RST proves a live stack even if no service listens.
            bool hostIsUp = icmpOk || anyTcpOpen || anyTcpClosed || snmpResponded;

            if (!hostIsUp)
            {
                // Filtered means a firewall/ACL silently dropped our packets.
                // That's a different failure mode than no signal at all, so surface it as Partial
                // (host may be present behind a firewall) rather than Unreachable (network path dead).
                if (tcpScanned && anyTcpFiltered) return ProbeStatus.Partial;
                return ProbeStatus.Unreachable;
            }

            bool tcpHealthy = !tcpScanned || anyTcpOpen;
            bool snmpHealthy = !target.RunSnmpProbe || snmpResponded;

            if (icmpOk && tcpHealthy && snmpHealthy)
            {
                return ProbeStatus.Reachable;
            }

            return ProbeStatus.Partial;
        }

        private static string BuildSummary(HostProbeResult host, ProbeTarget target, bool snmpResponded)
        {
            var parts = new List<string>();

            if (target.RunRouteCheck)
            {
                parts.Add(host.RouteStatus switch
                {
                    RouteStatus.Local => "route: on-link",
                    RouteStatus.ViaGateway => $"route: via {host.RouteGateway ?? "gateway"}",
                    RouteStatus.NoRoute => "route: none",
                    _ => "route: unknown"
                });
            }

            if (target.RunIcmpPing)
            {
                parts.Add(host.IcmpStatus switch
                {
                    IcmpStatus.Reply => host.IcmpRttMs.HasValue ? $"ICMP reply {host.IcmpRttMs} ms" : "ICMP reply",
                    IcmpStatus.NoReply => "no ICMP reply",
                    IcmpStatus.Error => "ICMP error",
                    _ => "ICMP unknown"
                });
            }

            if (target.RunTcpScan && host.TcpPorts.Count > 0)
            {
                var openPorts = host.TcpPorts.Where(kv => kv.Value == PortStatus.Open).Select(kv => kv.Key).OrderBy(p => p).ToList();
                parts.Add(openPorts.Count > 0
                    ? $"TCP open: {string.Join(",", openPorts)}"
                    : "no TCP ports open");
            }

            if (target.RunSnmpProbe)
            {
                parts.Add(snmpResponded ? "SNMP responded" : "no SNMP response");
            }

            return string.Join("; ", parts);
        }

        private async Task PersistFinalAsync(ReachabilityRun run)
        {
            try
            {
                await _database.UpdateReachabilityRunAsync(run).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Failed to persist final reachability run record");
            }
        }

        private static string SafeSerialize<T>(T value)
        {
            try
            {
                return JsonSerializer.Serialize(value, new JsonSerializerOptions
                {
                    WriteIndented = false
                });
            }
            catch
            {
                return string.Empty;
            }
        }

        private static void PublishHost(Action<HostProbeResult>? callback, HostProbeResult host)
        {
            if (callback == null) return;
            try
            {
                var app = Application.Current;
                if (app?.Dispatcher != null && !app.Dispatcher.CheckAccess())
                {
                    app.Dispatcher.InvokeAsync(() => callback(host));
                }
                else
                {
                    callback(host);
                }
            }
            catch (Exception ex)
            {
                Logger.Debug(ex, "Host update callback failed");
            }
        }

        private static void PublishRun(Action<ReachabilityRun>? callback, ReachabilityRun run)
        {
            if (callback == null) return;
            try
            {
                var app = Application.Current;
                if (app?.Dispatcher != null && !app.Dispatcher.CheckAccess())
                {
                    app.Dispatcher.InvokeAsync(() => callback(run));
                }
                else
                {
                    callback(run);
                }
            }
            catch (Exception ex)
            {
                Logger.Debug(ex, "Run completion callback failed");
            }
        }

        private void ResetState()
        {
            try { _cts?.Dispose(); } catch { }
            _cts = null;
            Interlocked.Exchange(ref _isRunning, 0);
        }
    }
}
