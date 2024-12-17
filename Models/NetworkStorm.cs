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
        public string GatewayIp { get; private set; }
        public byte[] GatewayMac { get; private set; }
        public bool EnableLogging { get; set; }

        public NetworkStorm(TextBox logArea)
        {
            _logArea = logArea ?? throw new ArgumentNullException(nameof(logArea));
            _logger = new AttackLogger(logArea);
            SourceIp = string.Empty;
            SourceMac = Array.Empty<byte>();
            GatewayIp = string.Empty;
            GatewayMac = Array.Empty<byte>();
        }

        public void Initialize(string sourceIp, byte[] sourceMac)
        {
            SourceIp = sourceIp;
            SourceMac = sourceMac;
        }

        public void SetSourceInfo(string sourceIp, byte[] sourceMac)
        {
            SourceIp = sourceIp;
            SourceMac = sourceMac;
        }

        public void SetGatewayIp(string gatewayIp)
        {
            GatewayIp = gatewayIp;
        }

        public async Task SetGatewayMacAsync(byte[] mac)
        {
            GatewayMac = mac;
        }

        private async Task<byte[]> GetMacAddressAsync(string ipAddress)
        {
            try
            {
                if (string.IsNullOrEmpty(ipAddress))
                    return Array.Empty<byte>();

                var addr = IPAddress.Parse(ipAddress);
                var macAddr = new byte[6];
                var macAddrLen = (uint)macAddr.Length;

                var result = await Task.Run(() => SendARP(
                    BitConverter.ToInt32(addr.GetAddressBytes(), 0),
                    0,
                    macAddr,
                    ref macAddrLen));

                if (result != 0)
                    return Array.Empty<byte>();

                return macAddr;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error getting MAC address: {ex.Message}");
                return Array.Empty<byte>();
            }
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

            try
            {
                _cancellationSource = new CancellationTokenSource();
                _isAttackRunning = true;

                byte[] macToUse;
                if (!IsOnSameSubnet(IPAddress.Parse(SourceIp), IPAddress.Parse(targetIp)))
                {
                    if (GatewayMac.Length == 0)
                    {
                        throw new Exception("Gateway MAC address is required for cross-subnet attacks");
                    }
                    macToUse = GatewayMac;
                    _logger.LogInfo($"Using Gateway MAC for cross-subnet attack: {BitConverter.ToString(GatewayMac).Replace("-", ":")}");
                }
                else
                {
                    var targetMac = await GetMacAddressAsync(targetIp);
                    if (targetMac.Length == 0)
                    {
                        throw new Exception("Could not resolve target MAC address");
                    }
                    macToUse = targetMac;
                    _logger.LogInfo($"Using Target MAC for same-subnet attack: {BitConverter.ToString(targetMac).Replace("-", ":")}");
                }

                _logger.StartAttack(attackType, SourceIp, SourceMac, targetIp, macToUse, megabitsPerSecond);

                var bytesPerSecond = megabitsPerSecond * 125_000; // Convert Mbps to Bytes/s
                switch (attackType)
                {
                    case AttackType.UdpFlood:
                        using (var udpFlood = new UdpFlood(SourceIp, SourceMac, targetIp, macToUse, GatewayMac, targetPort, bytesPerSecond, _cancellationSource.Token))
                        {
                            await udpFlood.StartAsync();
                        }
                        break;
                    case AttackType.IcmpFlood:
                        using (var icmpFlood = new IcmpFlood(
                            SourceIp,
                            SourceMac,
                            targetIp,
                            macToUse,
                            GatewayMac,
                            bytesPerSecond,
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
                            macToUse,
                            GatewayMac,
                            targetPort,
                            bytesPerSecond,
                            _cancellationSource.Token))
                        {
                            await tcpFlood.StartAsync();
                        }
                        break;
                    default:
                        Log("Unknown Attack Type.");
                        break;
                }

                _logger.LogInfo("Attack finished successfully.");
                _logger.LogInfo("━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Attack failed: {ex.Message}");
                _logger.LogInfo("━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                throw;
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
                _cancellationSource?.Cancel();
                _isAttackRunning = false;
                _logger.LogInfo("Attack stop signal sent.");
            }
            finally
            {
                if (_cancellationSource != null)
                {
                    await Task.Delay(100); // Give time for cleanup
                    _cancellationSource.Dispose();
                    _cancellationSource = null;
                }
            }
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