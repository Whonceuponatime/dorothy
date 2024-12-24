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
using System.Diagnostics;
using System.Text;
using System.Net.Sockets;
using System.Net.NetworkInformation;

namespace Dorothy.Models
{
    public class NetworkStorm
    {
        private readonly AttackLogger _logger;
        private readonly TextBox _logArea;
        private bool _isAttackRunning;
        private CancellationTokenSource? _cancellationSource;
        private CancellationTokenSource? _gatewayResolutionCts;
        public string SourceIp { get; private set; }
        public byte[] SourceMac { get; private set; }
        public string GatewayIp { get; private set; }
        public byte[] GatewayMac { get; private set; }
        public bool EnableLogging { get; set; }
        public string TargetIp { get; private set; } = string.Empty;

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

        public async Task SetGatewayIp(string gatewayIp)
        {
            GatewayIp = gatewayIp;
            
            // Only proceed if we have a potentially valid IP address
            if (gatewayIp.Count(c => c == '.') == 3 && gatewayIp.Length >= 7)
            {
                try
                {
                    // Cancel any previous resolution attempt
                    _gatewayResolutionCts?.Cancel();
                    _gatewayResolutionCts = new CancellationTokenSource();
                    
                    // Wait for typing to finish (500ms delay)
                    await Task.Delay(500, _gatewayResolutionCts.Token);
                    
                    // Validate IP format before attempting resolution
                    if (IPAddress.TryParse(gatewayIp, out _))
                    {
                        var gatewayMac = await GetMacAddressAsync(gatewayIp);
                        if (gatewayMac.Length > 0)
                        {
                            GatewayMac = gatewayMac;
                            _logger.LogInfo($"Gateway MAC resolved: {BitConverter.ToString(gatewayMac).Replace("-", ":")}");
                        }
                    }
                }
                catch (OperationCanceledException)
                {
                    // Ignore cancellation
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Error resolving Gateway MAC: {ex.Message}");
                }
                finally
                {
                    _gatewayResolutionCts?.Dispose();
                    _gatewayResolutionCts = null;
                }
            }
        }

        public async Task SetGatewayMacAsync(byte[] mac)
        {
            GatewayMac = mac;
            await Task.CompletedTask;
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
            TargetIp = targetIp;
            
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
                string macDisplay;
                if (!IsOnSameSubnet(IPAddress.Parse(SourceIp), IPAddress.Parse(targetIp)))
                {
                    if (GatewayMac.Length == 0)
                    {
                        throw new Exception("Gateway MAC address is required for cross-subnet attacks");
                    }
                    macToUse = GatewayMac;
                    macDisplay = $"{BitConverter.ToString(GatewayMac).Replace("-", ":")} (Gateway MAC)";
                    _logger.LogInfo($"Using Gateway MAC for cross-subnet attack: {macDisplay}");
                }
                else
                {
                    var targetMac = await GetMacAddressAsync(targetIp);
                    if (targetMac.Length == 0)
                    {
                        throw new Exception("Could not resolve target MAC address");
                    }
                    macToUse = targetMac;
                    macDisplay = BitConverter.ToString(targetMac).Replace("-", ":");
                    _logger.LogInfo($"Using Target MAC for same-subnet attack: {macDisplay}");
                }

                _logger.StartAttack(attackType, SourceIp, SourceMac, targetIp, macToUse, megabitsPerSecond);
                _logger.LogInfo($"Target MAC: {macDisplay}");

                var bytesPerSecond = megabitsPerSecond * 125_000;
                switch (attackType)
                {
                    case AttackType.UdpFlood:
                        using (var udpFlood = new UdpFlood(SourceIp, SourceMac, targetIp, macToUse, GatewayMac, targetPort, bytesPerSecond, _cancellationSource.Token))
                        {
                            await udpFlood.StartAsync();
                        }
                        break;
                    case AttackType.IcmpFlood:
                        using (var icmpFlood = new IcmpFlood(SourceIp, SourceMac, targetIp, macToUse, GatewayMac, bytesPerSecond, _cancellationSource.Token))
                        {
                            await icmpFlood.StartAsync();
                        }
                        break;
                    case AttackType.SynFlood:
                        using (var tcpFlood = new TcpFlood(SourceIp, SourceMac, targetIp, macToUse, GatewayMac, targetPort, bytesPerSecond, _cancellationSource.Token))
                        {
                            await tcpFlood.StartAsync();
                        }
                        break;
                    default:
                        throw new ArgumentException($"Unsupported attack type: {attackType}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Attack failed: {ex.Message}");
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
                // Get target network before stopping
                string targetNetwork = GetNetworkAddress(TargetIp);
                
                _cancellationSource?.Cancel();
                _isAttackRunning = false;
                
                // Remove the route if it exists
                if (!string.IsNullOrEmpty(targetNetwork))
                {
                    await RemoveRouteAsync(targetNetwork);
                }
                
                _logger.LogInfo("Attack stop signal sent.");
            }
            finally
            {
                if (_cancellationSource != null)
                {
                    await Task.Delay(100);
                    _cancellationSource.Dispose();
                    _cancellationSource = null;
                }
            }
        }

        private bool IsOnSameSubnet(IPAddress ip1, IPAddress ip2)
        {
            var networkInterface = CaptureDeviceList.Instance
                .OfType<LibPcapLiveDevice>()
                .FirstOrDefault(d => d.Addresses.Any(addr => 
                    addr.Addr?.ipAddress != null && 
                    addr.Addr.ipAddress.ToString() == ip1.ToString()));

            if (networkInterface != null)
            {
                var ipProps = networkInterface.Addresses
                    .FirstOrDefault(a => a.Addr?.ipAddress != null && 
                                        a.Addr.ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
                
                if (ipProps?.Netmask?.ipAddress != null)
                {
                    byte[] subnet = ipProps.Netmask.ipAddress.GetAddressBytes();
                    byte[] bytes1 = ip1.GetAddressBytes();
                    byte[] bytes2 = ip2.GetAddressBytes();
                    
                    for (int i = 0; i < 4; i++)
                    {
                        if ((bytes1[i] & subnet[i]) != (bytes2[i] & subnet[i]))
                            return false;
                    }
                    return true;
                }
            }
            
            // Fallback to default /24 subnet if we can't get the actual mask
            byte[] defaultSubnet = new byte[] { 255, 255, 255, 0 };
            byte[] addr1 = ip1.GetAddressBytes();
            byte[] addr2 = ip2.GetAddressBytes();
            
            for (int i = 0; i < 4; i++)
            {
                if ((addr1[i] & defaultSubnet[i]) != (addr2[i] & defaultSubnet[i]))
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

        public async Task AddRouteAsync(string targetNetwork, string gatewayIp)
        {
            try
            {
                // Always use the gateway IP provided by user for cross-subnet routing
                string routerIp = gatewayIp;
                
                // Remove any existing route first
                await RemoveRouteAsync(targetNetwork);

                var startInfo = new ProcessStartInfo
                {
                    FileName = "route",
                    Arguments = $"add {targetNetwork} mask 255.255.255.0 {routerIp}",
                    UseShellExecute = true,
                    Verb = "runas",
                    CreateNoWindow = true
                };

                using var process = Process.Start(startInfo);
                if (process != null)
                {
                    await process.WaitForExitAsync();
                    if (process.ExitCode == 0)
                    {
                        _logger.LogInfo($"Route added successfully: {targetNetwork} via {routerIp}");
                    }
                    else
                    {
                        _logger.LogError($"Failed to add route. Exit code: {process.ExitCode}");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error adding route: {ex.Message}");
                throw;
            }
        }

        public async Task RemoveRouteAsync(string targetNetwork)
        {
            try
            {
                var startInfo = new ProcessStartInfo
                {
                    FileName = "route",
                    Arguments = $"delete {targetNetwork}",
                    UseShellExecute = true,
                    Verb = "runas",
                    CreateNoWindow = true
                };

                using var process = Process.Start(startInfo);
                if (process != null)
                {
                    await process.WaitForExitAsync();
                    if (process.ExitCode == 0)
                    {
                        _logger.LogInfo($"Route removed successfully: {targetNetwork}");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error removing route: {ex.Message}");
            }
        }

        private string GetNetworkAddress(string ipAddress)
        {
            try
            {
                if (IPAddress.TryParse(ipAddress, out var ip))
                {
                    var bytes = ip.GetAddressBytes();
                    return $"{bytes[0]}.{bytes[1]}.{bytes[2]}.0";
                }
            }
            catch { }
            return string.Empty;
        }

        public async Task<bool> CheckConnectivityAsync(string targetIp)
        {
            try
            {
                var ping = new Ping();
                var reply = await ping.SendPingAsync(targetIp, 1000);
                return reply.Status == IPStatus.Success;
            }
            catch
            {
                return false;
            }
        }

        public async Task<string> GetRoutingDiagnosticsAsync(string targetIp)
        {
            var diagnostics = new StringBuilder();
            var sourceIpObj = IPAddress.Parse(SourceIp);
            var targetIpObj = IPAddress.Parse(targetIp);
            
            diagnostics.AppendLine($"Source IP: {SourceIp}");
            diagnostics.AppendLine($"Target IP: {targetIp}");
            
            if (!IsOnSameSubnet(sourceIpObj, targetIpObj))
            {
                diagnostics.AppendLine("Different subnets detected - Routing required");
                diagnostics.AppendLine($"Gateway IP: {GatewayIp}");
                if (GatewayMac.Length > 0)
                {
                    diagnostics.AppendLine($"Gateway MAC: {BitConverter.ToString(GatewayMac).Replace("-", ":")}");
                }
                else
                {
                    diagnostics.AppendLine("Warning: Gateway MAC not resolved");
                }
            }
            
            var pingResult = await CheckConnectivityAsync(targetIp);
            diagnostics.AppendLine($"Ping test: {(pingResult ? "Success" : "Failed")}");
            
            return diagnostics.ToString();
        }

        private NetworkInterface? GetActiveNetworkInterface()
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .FirstOrDefault(ni => 
                    ni.OperationalStatus == OperationalStatus.Up && 
                    ni.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                    ni.GetIPProperties().UnicastAddresses.Any(addr => 
                        addr.Address.AddressFamily == AddressFamily.InterNetwork));
        }

        public async Task<string> GetGatewayMacAsync()
        {
            try
            {
                if (GatewayMac != null && GatewayMac.Length > 0)
                {
                    return BitConverter.ToString(GatewayMac).Replace("-", ":");
                }
                
                if (string.IsNullOrEmpty(GatewayIp))
                {
                    return string.Empty;
                }

                var mac = await GetMacAddressAsync(GatewayIp);
                if (mac.Length > 0)
                {
                    GatewayMac = mac;
                    return BitConverter.ToString(mac).Replace("-", ":");
                }
                
                return string.Empty;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error getting gateway MAC: {ex.Message}");
                return string.Empty;
            }
        }
    }
}