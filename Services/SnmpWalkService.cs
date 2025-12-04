using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;
using Lextm.SharpSnmpLib.Security;
using Dorothy.Models;

namespace Dorothy.Services
{
    /// <summary>
    /// Service for performing SNMP walk operations with common community strings
    /// </summary>
    public class SnmpWalkService
    {
        private readonly AttackLogger _logger;
        private CancellationTokenSource? _cancellationTokenSource;

        // Common SNMP community strings (100 most common)
        private static readonly string[] CommonCommunityStrings = new string[]
        {
            "public", "private", "community", "admin", "administrator",
            "read", "write", "readwrite", "rw", "ro",
            "cisco", "hp", "3com", "d-link", "netgear",
            "linksys", "default", "password", "pass", "1234",
            "snmp", "public1", "private1", "public2", "private2",
            "manager", "monitor", "test", "demo", "guest",
            "user", "root", "system", "network", "device",
            "router", "switch", "firewall", "server", "printer",
            "camera", "sensor", "controller", "gateway", "access",
            "control", "monitoring", "management", "admin123", "password123",
            "admin1", "admin2", "admin3", "root123", "system123",
            "cisco123", "hp123", "netgear123", "dlink", "linksys123",
            "public123", "private123", "read123", "write123", "snmp123",
            "default123", "test123", "demo123", "guest123", "user123",
            "manager123", "monitor123", "network123", "device123", "router123",
            "switch123", "firewall123", "server123", "printer123", "camera123",
            "sensor123", "controller123", "gateway123", "access123", "control123",
            "monitoring123", "management123", "adminadmin", "passwordpassword", "publicpublic",
            "privateprivate", "readread", "writewrite", "snmp snmp", "defaultdefault",
            "testtest", "demodemo", "guestguest", "useruser", "managermanager",
            "monitormonitor", "networknetwork", "devicedevice", "routerrouter", "switchswitch"
        };

        public SnmpWalkService(AttackLogger logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Perform SNMP walk with common community strings
        /// </summary>
        public async Task<SnmpWalkResult> WalkAsync(
            string targetIp,
            int port,
            IProgress<(string message, int percent)>? progress,
            CancellationToken cancellationToken)
        {
            var result = new SnmpWalkResult
            {
                TargetIp = targetIp,
                Port = port,
                StartTime = DateTime.Now
            };

            int totalCommunities = CommonCommunityStrings.Length;
            int completedAttempts = 0;
            object lockObject = new object();

            _logger.LogInfo($"[SNMP Walk] Starting SNMP walk on {targetIp}:{port} with {totalCommunities} common community strings");

            progress?.Report(($"[SNMP Walk] Starting walk with {totalCommunities} community strings...", 0));

            var tasks = new List<Task>();
            var semaphore = new SemaphoreSlim(10); // Limit concurrent attempts

            foreach (var community in CommonCommunityStrings)
            {
                if (cancellationToken.IsCancellationRequested)
                    break;

                await semaphore.WaitAsync(cancellationToken);

                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        var communityResult = await TryCommunityStringAsync(targetIp, port, community, cancellationToken);
                        
                        lock (result)
                        {
                            result.Attempts++;
                            if (communityResult.Success)
                            {
                                result.SuccessfulCommunity = community;
                                result.SuccessfulOids = communityResult.Oids;
                                result.Success = true;
                            }
                        }

                        lock (lockObject)
                        {
                            completedAttempts++;
                            int percent = totalCommunities > 0 ? (completedAttempts * 100) / totalCommunities : 0;
                            
                            if (communityResult.Success)
                            {
                                progress?.Report(($"[SNMP Walk] ✓ Success with community: {community} (found {communityResult.Oids.Count} OIDs) ({completedAttempts}/{totalCommunities})", percent));
                                _logger.LogSuccess($"[SNMP Walk] Successfully authenticated with community '{community}' on {targetIp}:{port}. Found {communityResult.Oids.Count} OIDs.");
                            }
                            else
                            {
                                progress?.Report(($"[SNMP Walk] ✗ Failed: {community} ({completedAttempts}/{totalCommunities})", percent));
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        lock (result)
                        {
                            result.Attempts++;
                        }
                        lock (lockObject)
                        {
                            completedAttempts++;
                            int percent = totalCommunities > 0 ? (completedAttempts * 100) / totalCommunities : 0;
                            progress?.Report(($"[SNMP Walk] Error with {community}: {ex.Message} ({completedAttempts}/{totalCommunities})", percent));
                        }
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                }, cancellationToken));
            }

            await Task.WhenAll(tasks);
            
            progress?.Report(("SNMP walk completed.", 100));
            
            result.EndTime = DateTime.Now;
            result.Duration = result.EndTime - result.StartTime;

            if (result.Success)
            {
                _logger.LogSuccess($"[SNMP Walk] Completed: Successfully authenticated with '{result.SuccessfulCommunity}' on {targetIp}:{port}. Total attempts: {result.Attempts}, Duration: {result.Duration.TotalSeconds:F2}s");
            }
            else
            {
                _logger.LogWarning($"[SNMP Walk] Completed: No successful authentication after {result.Attempts} attempts on {targetIp}:{port}. Duration: {result.Duration.TotalSeconds:F2}s");
            }

            return result;
        }

        private async Task<CommunityWalkResult> TryCommunityStringAsync(
            string targetIp,
            int port,
            string community,
            CancellationToken cancellationToken)
        {
            var result = new CommunityWalkResult { Community = community };
            var oids = new List<string>();

            try
            {
                var ip = IPAddress.Parse(targetIp);
                var endpoint = new IPEndPoint(ip, port);
                var communityObject = new OctetString(community);

                // Start with system.sysDescr (1.3.6.1.2.1.1.1.0)
                var startOid = new ObjectIdentifier("1.3.6.1.2.1.1");
                
                await Task.Run(() =>
                {
                    try
                    {
                        var variables = new List<Variable>();
                        var resultList = Messenger.Walk(
                            VersionCode.V2,
                            endpoint,
                            communityObject,
                            startOid,
                            variables,
                            5000, // 5 second timeout per request
                            WalkMode.WithinSubtree);

                        foreach (var variable in variables)
                        {
                            if (cancellationToken.IsCancellationRequested)
                                break;

                            try
                            {
                                var oid = variable.Id.ToString();
                                var value = variable.Data?.ToString() ?? "null";
                                oids.Add($"{oid} = {value}");
                            }
                            catch
                            {
                                // Ignore individual OID errors
                            }
                        }

                        result.Success = true;
                        result.Oids = oids;
                    }
                    catch (SocketException)
                    {
                        // Connection refused or timeout
                        result.Success = false;
                    }
                    catch (Lextm.SharpSnmpLib.Messaging.TimeoutException)
                    {
                        // Request timeout
                        result.Success = false;
                    }
                    catch (Exception)
                    {
                        // Other errors (authentication failed, etc.)
                        result.Success = false;
                    }
                }, cancellationToken);
            }
            catch
            {
                result.Success = false;
            }

            return result;
        }
    }

    public class SnmpWalkResult
    {
        public string TargetIp { get; set; } = string.Empty;
        public int Port { get; set; }
        public bool Success { get; set; }
        public string? SuccessfulCommunity { get; set; }
        public List<string> SuccessfulOids { get; set; } = new List<string>();
        public int Attempts { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public TimeSpan Duration { get; set; }
    }

    public class CommunityWalkResult
    {
        public string Community { get; set; } = string.Empty;
        public bool Success { get; set; }
        public List<string> Oids { get; set; } = new List<string>();
    }
}

