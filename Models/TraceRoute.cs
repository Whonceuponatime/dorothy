using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Text;
using System.Linq;

namespace Dorothy.Models
{
    public class TraceRoute
    {
        private readonly AttackLogger _logger;
        private const int Timeout = 5000;
        private const int MaxHops = 30;

        public TraceRoute(AttackLogger logger)
        {
            _logger = logger;
        }

        public async Task ExecuteTraceRouteAsync(string targetIp)
        {
            try
            {
                var hops = new List<(int Hop, long RoundTripTime, string Address, string? HostName)>();
                _logger.LogInfo($"Starting traceroute to {targetIp}...");
                _logger.LogInfo("━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

                for (int ttl = 1; ttl <= MaxHops; ttl++)
                {
                    var (address, roundTripTime) = await SendPingAsync(targetIp, ttl);
                    
                    if (address == null)
                    {
                        _logger.LogInfo($"{ttl,2} *  Request timed out.");
                        continue;
                    }

                    string? hostName = null;
                    try
                    {
                        var hostEntry = await Dns.GetHostEntryAsync(address);
                        hostName = hostEntry.HostName;
                        _logger.LogInfo($"{ttl,2} {roundTripTime,4} ms  {address} [{hostName}]");
                    }
                    catch
                    {
                        _logger.LogInfo($"{ttl,2} {roundTripTime,4} ms  {address}");
                    }

                    hops.Add((ttl, roundTripTime, address.ToString(), hostName));

                    if (address.ToString() == targetIp)
                    {
                        _logger.LogInfo("━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                        _logger.LogInfo("Trace complete.");

                        // Generate and log summary
                        var summary = GenerateTraceSummary(targetIp, hops);
                        _logger.LogInfo("\nTrace Route Summary:");
                        _logger.LogInfo("━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                        _logger.LogInfo(summary);
                        _logger.LogInfo("━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                        break;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Traceroute failed: {ex.Message}");
                throw;
            }
        }

        private async Task<(IPAddress? Address, long RoundTripTime)> SendPingAsync(string targetIp, int ttl)
        {
            using var ping = new Ping();
            var options = new PingOptions(ttl, true);
            byte[] buffer = new byte[32];

            try
            {
                var reply = await ping.SendPingAsync(targetIp, Timeout, buffer, options);
                
                if (reply.Status == IPStatus.TtlExpired || reply.Status == IPStatus.Success)
                {
                    return (reply.Address, reply.RoundtripTime);
                }
            }
            catch (PingException)
            {
                // Ignore ping exceptions and treat as timeout
            }

            return (null, 0);
        }

        private string GenerateTraceSummary(string targetIp, List<(int Hop, long RoundTripTime, string Address, string? HostName)> hops)
        {
            var summary = new StringBuilder();
            
            // Add target information
            summary.AppendLine($"Target: {targetIp}");
            summary.AppendLine($"Total Hops: {hops.Count}");
            
            // Calculate statistics
            var totalTime = hops.Sum(h => h.RoundTripTime);
            var avgTime = hops.Count > 0 ? totalTime / hops.Count : 0;
            var maxTime = hops.Max(h => h.RoundTripTime);
            var minTime = hops.Min(h => h.RoundTripTime);
            
            summary.AppendLine($"Average Response Time: {avgTime} ms");
            summary.AppendLine($"Fastest Response: {minTime} ms");
            summary.AppendLine($"Slowest Response: {maxTime} ms");

            // Identify key points in the route
            if (hops.Count > 0)
            {
                summary.AppendLine("\nKey Points:");
                // First hop (usually local gateway)
                var firstHop = hops[0];
                summary.AppendLine($"Gateway: {firstHop.Address}" + (firstHop.HostName != null ? $" [{firstHop.HostName}]" : ""));
                
                // Last hop (destination)
                var lastHop = hops[^1];
                summary.AppendLine($"Destination: {lastHop.Address}" + (lastHop.HostName != null ? $" [{lastHop.HostName}]" : ""));

                // Identify any significant latency jumps
                for (int i = 1; i < hops.Count; i++)
                {
                    var latencyJump = hops[i].RoundTripTime - hops[i - 1].RoundTripTime;
                    if (latencyJump > 20) // Significant jump threshold
                    {
                        summary.AppendLine($"Significant Latency Jump at Hop {hops[i].Hop}: +{latencyJump}ms");
                    }
                }
            }

            return summary.ToString();
        }
    }
} 