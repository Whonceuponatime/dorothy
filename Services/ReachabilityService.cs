using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Dorothy.Models;

namespace Dorothy.Services
{
    /// <summary>
    /// Service for testing host reachability via ICMP and TCP
    /// </summary>
    public class ReachabilityService
    {
        private readonly int[] _defaultReachabilityPorts = { 22, 80, 443, 3389 };
        private readonly int _pingTimeout = 2000; // 2 seconds
        private readonly int _tcpConnectTimeout = 2000; // 2 seconds
        private readonly int _pingCount = 3;

        /// <summary>
        /// Test reachability of a host using ICMP ping and TCP probes
        /// </summary>
        public async Task<HostReachabilityResult> TestReachabilityAsync(
            string ipAddress, 
            CancellationToken cancellationToken = default)
        {
            var result = new HostReachabilityResult
            {
                IpAddress = ipAddress
            };

            try
            {
                // Primary test: ICMP ping
                result.PingSuccess = await TestIcmpPingAsync(ipAddress, cancellationToken);
                result.PingCount = _pingCount;
                result.PingSuccessCount = result.PingSuccess ? _pingCount : 0;

                if (result.PingSuccess)
                {
                    result.State = ReachabilityState.ReachableIcmp;
                    return result;
                }

                // Secondary test: TCP reachability check
                var reachableTcpPorts = await TestTcpReachabilityAsync(ipAddress, cancellationToken);
                result.ReachableTcpPorts = reachableTcpPorts;

                if (reachableTcpPorts.Count > 0)
                {
                    result.State = ReachabilityState.ReachableTcpOnly;
                }
                else
                {
                    result.State = ReachabilityState.Unreachable;
                }
            }
            catch (Exception ex)
            {
                result.State = ReachabilityState.Unknown;
                result.ErrorMessage = ex.Message;
            }

            return result;
        }

        /// <summary>
        /// Test if firewall interface is reachable
        /// </summary>
        public async Task<bool> TestFirewallInterfaceReachabilityAsync(
            string firewallIp, 
            CancellationToken cancellationToken = default)
        {
            try
            {
                var result = await TestReachabilityAsync(firewallIp, cancellationToken);
                return result.State == ReachabilityState.ReachableIcmp || 
                       result.State == ReachabilityState.ReachableTcpOnly;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Test ICMP ping to a host
        /// </summary>
        private async Task<bool> TestIcmpPingAsync(
            string ipAddress, 
            CancellationToken cancellationToken)
        {
            try
            {
                using var ping = new Ping();
                int successCount = 0;

                for (int i = 0; i < _pingCount; i++)
                {
                    if (cancellationToken.IsCancellationRequested)
                        break;

                    try
                    {
                        var reply = await ping.SendPingAsync(ipAddress, _pingTimeout);
                        if (reply != null && reply.Status == IPStatus.Success)
                        {
                            successCount++;
                        }
                    }
                    catch
                    {
                        // Ping failed, continue to next attempt
                    }

                    // Small delay between pings
                    if (i < _pingCount - 1)
                    {
                        await Task.Delay(200, cancellationToken);
                    }
                }

                // Consider reachable if at least one ping succeeded
                return successCount > 0;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Test TCP reachability by attempting connections to default ports
        /// </summary>
        private async Task<List<int>> TestTcpReachabilityAsync(
            string ipAddress, 
            CancellationToken cancellationToken)
        {
            var reachablePorts = new List<int>();

            foreach (var port in _defaultReachabilityPorts)
            {
                if (cancellationToken.IsCancellationRequested)
                    break;

                try
                {
                    using var client = new TcpClient();
                    var connectTask = client.ConnectAsync(ipAddress, port);
                    var timeoutTask = Task.Delay(_tcpConnectTimeout, cancellationToken);

                    var completedTask = await Task.WhenAny(connectTask, timeoutTask);

                    if (completedTask == connectTask && client.Connected)
                    {
                        // Connection succeeded - host is reachable
                        reachablePorts.Add(port);
                        // Close connection immediately
                        client.Close();
                    }
                    else if (completedTask == connectTask)
                    {
                        // Connection attempt completed but not connected
                        // Check for connection refused (host reachable, port closed)
                        try
                        {
                            // If we get here, the host responded (even if refused)
                            // This indicates the host is reachable
                            reachablePorts.Add(port);
                        }
                        catch
                        {
                            // Ignore errors
                        }
                    }
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionRefused)
                {
                    // Connection refused means host is reachable, port is just closed
                    reachablePorts.Add(port);
                }
                catch
                {
                    // Timeout or other error - port is likely filtered or host unreachable
                }
            }

            return reachablePorts;
        }
    }
}






