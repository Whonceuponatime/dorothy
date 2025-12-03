using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Dorothy.Models;

namespace Dorothy.Services
{
    /// <summary>
    /// Service for discovering firewall rules by testing port connectivity
    /// </summary>
    public class FirewallRuleDiscoveryService
    {
        private readonly int _tcpConnectTimeout = 2000; // 2 seconds

        /// <summary>
        /// Discover firewall rules for a reachable host by testing ports
        /// </summary>
        public async Task<HostFirewallAnalysis> DiscoverRulesAsync(
            string ipAddress,
            string label,
            ReachabilityState reachability,
            List<int> portList,
            CancellationToken cancellationToken = default)
        {
            var analysis = new HostFirewallAnalysis
            {
                IpAddress = ipAddress,
                Label = label,
                Reachability = reachability
            };

            // Only discover rules if host is reachable
            if (reachability != ReachabilityState.ReachableIcmp && 
                reachability != ReachabilityState.ReachableTcpOnly)
            {
                return analysis;
            }

            var ruleResults = new List<FirewallRuleResult>();

            foreach (var port in portList)
            {
                if (cancellationToken.IsCancellationRequested)
                    break;

                var ruleResult = await TestPortAsync(ipAddress, port, cancellationToken);
                if (ruleResult != null)
                {
                    ruleResults.Add(ruleResult);
                }
            }

            analysis.RuleResults = ruleResults;
            return analysis;
        }

        /// <summary>
        /// Test a single port and classify the result
        /// </summary>
        private async Task<FirewallRuleResult?> TestPortAsync(
            string ipAddress,
            int port,
            CancellationToken cancellationToken)
        {
            var result = new FirewallRuleResult
            {
                Port = port,
                ServiceName = GetServiceName(port)
            };

            var stopwatch = Stopwatch.StartNew();

            try
            {
                if (cancellationToken.IsCancellationRequested)
                    return null;

                using var client = new TcpClient();
                try
                {
                    // Use ConnectAsync with configurable timeout
                    var connectTask = client.ConnectAsync(ipAddress, port);
                    var timeoutTask = Task.Delay(_tcpConnectTimeout, cancellationToken);

                    var completedTask = await Task.WhenAny(connectTask, timeoutTask);

                    if (cancellationToken.IsCancellationRequested)
                        return null;

                    stopwatch.Stop();
                    result.ResponseTime = stopwatch.Elapsed;

                    if (completedTask == timeoutTask)
                    {
                        // Timeout - port is likely filtered or closed
                        result.Action = FirewallRuleAction.FilteredTimeout;
                        return result;
                    }

                    // Check if connection succeeded
                    if (client.Connected)
                    {
                        // Connection succeeded - port is open and allowed
                        result.Action = FirewallRuleAction.AllowedOpen;
                        return result;
                    }
                }
                catch (OperationCanceledException)
                {
                    // Expected when cancellation is requested
                    return null;
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionRefused)
                {
                    // Connection refused - host is reachable, port is closed, no firewall drop
                    stopwatch.Stop();
                    result.ResponseTime = stopwatch.Elapsed;
                    result.Action = FirewallRuleAction.ClosedNoFirewall;
                    return result;
                }
                catch (SocketException)
                {
                    // Other socket errors - likely filtered
                    stopwatch.Stop();
                    result.ResponseTime = stopwatch.Elapsed;
                    result.Action = FirewallRuleAction.FilteredTimeout;
                    return result;
                }
                catch
                {
                    // Other errors - likely filtered
                    stopwatch.Stop();
                    result.ResponseTime = stopwatch.Elapsed;
                    result.Action = FirewallRuleAction.FilteredTimeout;
                    return result;
                }
            }
            catch (OperationCanceledException)
            {
                // Expected when cancellation is requested
                return null;
            }
            catch (Exception ex)
            {
                stopwatch.Stop();
                result.ResponseTime = stopwatch.Elapsed;
                result.Action = FirewallRuleAction.FilteredTimeout;
                result.ErrorMessage = ex.Message;
                return result;
            }

            // Default to filtered if we can't determine
            stopwatch.Stop();
            result.ResponseTime = stopwatch.Elapsed;
            result.Action = FirewallRuleAction.FilteredTimeout;
            return result;
        }

        /// <summary>
        /// Get service name for a port
        /// </summary>
        private string GetServiceName(int port)
        {
            return port switch
            {
                20 => "FTP Data",
                21 => "FTP",
                22 => "SSH",
                23 => "Telnet",
                25 => "SMTP",
                53 => "DNS",
                80 => "HTTP",
                110 => "POP3",
                135 => "RPC",
                139 => "NetBIOS",
                143 => "IMAP",
                443 => "HTTPS",
                445 => "SMB",
                465 => "SMTPS",
                514 => "Syslog",
                587 => "SMTP Submission",
                636 => "LDAPS",
                873 => "rsync",
                993 => "IMAPS",
                995 => "POP3S",
                1433 => "MSSQL",
                1521 => "Oracle",
                3306 => "MySQL",
                3389 => "RDP",
                5432 => "PostgreSQL",
                5900 => "VNC",
                8080 => "HTTP-Proxy",
                8443 => "HTTPS-Alt",
                9200 => "Elasticsearch",
                _ => $"Port {port}"
            };
        }
    }
}




