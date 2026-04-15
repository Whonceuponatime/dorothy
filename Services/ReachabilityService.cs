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

    public class ReachabilityService
    {
        private readonly int[] _defaultReachabilityPorts = { 22, 80, 443, 3389 };
        private readonly int _pingTimeout = 2000;
        private readonly int _tcpConnectTimeout = 2000;
        private readonly int _pingCount = 3;

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

                result.PingSuccess = await TestIcmpPingAsync(ipAddress, cancellationToken);
                result.PingCount = _pingCount;
                result.PingSuccessCount = result.PingSuccess ? _pingCount : 0;

                if (result.PingSuccess)
                {
                    result.State = ReachabilityState.ReachableIcmp;
                    return result;
                }

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

                    }

                    if (i < _pingCount - 1)
                    {
                        await Task.Delay(200, cancellationToken);
                    }
                }

                return successCount > 0;
            }
            catch
            {
                return false;
            }
        }

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

                        reachablePorts.Add(port);

                        client.Close();
                    }
                    else if (completedTask == connectTask)
                    {

                        try
                        {

                            reachablePorts.Add(port);
                        }
                        catch
                        {

                        }
                    }
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionRefused)
                {

                    reachablePorts.Add(port);
                }
                catch
                {

                }
            }

            return reachablePorts;
        }
    }
}

