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
using Dorothy.Network;
using Dorothy.Network.Headers;

namespace Dorothy.Models
{
    public class NetworkStorm
    {
        private readonly AttackLogger _logger;
        private readonly TextBox _logArea;
        private bool _isAttackRunning;
        private CancellationTokenSource? _cancellationSource;
        private CancellationTokenSource? _gatewayResolutionCts;
        private Socket? _socket;
        public string SourceIp { get; private set; }
        public byte[] SourceMac { get; private set; }
        public string GatewayIp { get; private set; }
        public byte[] GatewayMac { get; private set; }
        public bool EnableLogging { get; set; }
        public string TargetIp { get; private set; } = string.Empty;
        public event EventHandler<PacketEventArgs>? PacketSent;

        protected virtual void OnPacketSent(PacketEventArgs e)
        {
            PacketSent?.Invoke(this, e);
        }

        public NetworkStorm(TextBox logArea)
        {
            _logArea = logArea ?? throw new ArgumentNullException(nameof(logArea));
            _logger = new AttackLogger(logArea);
            SourceIp = string.Empty;
            SourceMac = Array.Empty<byte>();
            GatewayIp = string.Empty;
            GatewayMac = Array.Empty<byte>();
            InitializeSocket();
        }

        private void InitializeSocket()
        {
            try
            {
                _socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, System.Net.Sockets.ProtocolType.IP);
                _socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to initialize socket: {ex.Message}");
            }
        }

        private void SendPacket(byte[] packet, IPHeader ipHeader, TcpHeader? tcpHeader = null, IcmpHeader? icmpHeader = null)
        {
            try
            {
                _socket?.Send(packet);
                OnPacketSent(new PacketEventArgs(ipHeader, tcpHeader, icmpHeader));
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to send packet: {ex.Message}");
            }
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

        public async Task<byte[]> GetMacAddressAsync(string ipAddress)
        {
            try
            {
                if (string.IsNullOrEmpty(ipAddress))
                    return Array.Empty<byte>();

                var targetIp = IPAddress.Parse(ipAddress);
                var sourceIp = IPAddress.Parse(SourceIp);

                // For targets on different subnets, return gateway MAC
                if (!IsOnSameSubnet(sourceIp, targetIp))
                {
                    if (GatewayMac.Length > 0)
                    {
                        return GatewayMac;
                    }
                    else if (!string.IsNullOrEmpty(GatewayIp))
                    {
                        // Try to resolve gateway MAC if we don't have it
                        var macAddr = new byte[6];
                        var macAddrLen = (uint)macAddr.Length;
                        var gatewayIpObj = IPAddress.Parse(GatewayIp);
                        var gatewayIpInt = BitConverter.ToInt32(gatewayIpObj.GetAddressBytes(), 0);
                        var sourceIpInt = BitConverter.ToInt32(sourceIp.GetAddressBytes(), 0);

                        var result = await Task.Run(() => SendARP(gatewayIpInt, sourceIpInt, macAddr, ref macAddrLen));

                        if (result != 0)
                        {
                            _logger.LogError($"Failed to resolve gateway MAC address - Required for routed target {ipAddress}");
                            return Array.Empty<byte>();
                        }

                        GatewayMac = macAddr;
                        return macAddr;
                    }
                    else
                    {
                        _logger.LogError($"Gateway IP not configured - Required for routed target {ipAddress}");
                        return Array.Empty<byte>();
                    }
                }

                // For targets on same subnet, resolve their MAC directly
                var localMacAddr = new byte[6];
                var localMacAddrLen = (uint)localMacAddr.Length;
                var targetIpInt = BitConverter.ToInt32(targetIp.GetAddressBytes(), 0);
                var localSourceIpInt = BitConverter.ToInt32(sourceIp.GetAddressBytes(), 0);

                var localResult = await Task.Run(() => SendARP(targetIpInt, localSourceIpInt, localMacAddr, ref localMacAddrLen));

                if (localResult != 0)
                {
                    _logger.LogError($"Failed to resolve MAC address for local target {ipAddress}");
                    return Array.Empty<byte>();
                }

                return localMacAddr;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error resolving MAC address: {ex.Message}");
                return Array.Empty<byte>();
            }
        }

        private void Log(string message)
        {
            _logger.LogInfo(message);
        }

        private async Task<PacketParameters> CreatePacketParameters(string targetIp, int targetPort, long megabitsPerSecond)
        {
            var targetIpObj = IPAddress.Parse(targetIp);
            var sourceIpObj = IPAddress.Parse(SourceIp);
            
            // For targets on different subnets, use gateway MAC as destination
            byte[] destinationMac;
            if (!IsOnSameSubnet(sourceIpObj, targetIpObj))
            {
                if (GatewayMac.Length == 0)
                {
                    throw new InvalidOperationException("Gateway MAC address is required for cross-subnet communication");
                }
                _logger.LogDebug($"Using gateway MAC for routed target: {targetIp}");
                destinationMac = GatewayMac;
            }
            else
            {
                // For same subnet, try to get target's MAC
                destinationMac = await GetMacAddressAsync(targetIp);
                if (destinationMac.Length == 0)
                {
                    throw new InvalidOperationException("Could not resolve target MAC address for local subnet target");
                }
                _logger.LogDebug($"Using target MAC for local subnet target: {BitConverter.ToString(destinationMac).Replace("-", ":")}");
            }

            return new PacketParameters
            {
                SourceMac = SourceMac,
                DestinationMac = destinationMac,
                SourceIp = sourceIpObj,
                DestinationIp = targetIpObj,
                SourcePort = Random.Shared.Next(49152, 65535),
                DestinationPort = targetPort,
                BytesPerSecond = megabitsPerSecond * 125_000,
                Ttl = 128
            };
        }

        public async Task StartAttackAsync(AttackType attackType, string targetIp, int targetPort, long megabitsPerSecond)
        {
            TargetIp = targetIp;
            
            if (_isAttackRunning)
            {
                _logger.LogWarning("Attack already in progress");
                return;
            }

            try
            {
                _cancellationSource = new CancellationTokenSource();
                _isAttackRunning = true;

                // Validate and resolve MAC addresses
                var sourceIpObj = IPAddress.Parse(SourceIp);
                var targetIpObj = IPAddress.Parse(targetIp);
                
                // Only check gateway MAC for cross-subnet targets
                if (!IsOnSameSubnet(sourceIpObj, targetIpObj))
                {
                    if (GatewayMac.Length == 0)
                    {
                        _logger.LogError("Gateway MAC address not configured - Required for cross-subnet target");
                        throw new Exception("Gateway MAC address is required for cross-subnet targets");
                    }
                }

                // Common packet parameters
                var packetParams = await CreatePacketParameters(targetIp, targetPort, megabitsPerSecond);

                // Log attack details in the specified format
                var message = $"Attack Details\n" +
                             "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" +
                             $"Protocol: {attackType}\n" +
                             $"Source Host: {SourceIp}\n" +
                             $"Source MAC: {BitConverter.ToString(SourceMac).Replace("-", ":")}\n" +
                             $"Target Host: {targetIp}\n" +
                             $"Target MAC: {BitConverter.ToString(packetParams.DestinationMac).Replace("-", ":")}\n" +
                             $"Target Rate: {megabitsPerSecond:F2} Mbps\n" +
                             $"Attack Type: {attackType}\n" +
                             "Status: Attack Started";
                _logger.LogInfo(message);

                switch (attackType)
                {
                    case AttackType.UdpFlood:
                        using (var udpFlood = new UdpFlood(packetParams, _cancellationSource.Token))
                        {
                            await udpFlood.StartAsync();
                        }
                        break;

                    case AttackType.IcmpFlood:
                        using (var icmpFlood = new IcmpFlood(packetParams, _cancellationSource.Token))
                        {
                            await icmpFlood.StartAsync();
                        }
                        break;

                    case AttackType.SynFlood:
                        using (var tcpFlood = new TcpFlood(packetParams, _cancellationSource.Token))
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
                _isAttackRunning = false;
                _logger.LogError($"Attack failed: {ex.Message}");
                throw;
            }
        }

        public async Task StopAttackAsync()
        {
            if (!_isAttackRunning)
            {
                _logger.LogWarning("No attack is currently running");
                return;
            }

            try
            {
                _cancellationSource?.Cancel();
                _isAttackRunning = false;
                
                var message = "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" +
                             $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] Status: Attack Stopped";
                _logger.LogInfo(message);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error stopping attack: {ex.Message}");
                throw;
            }
            finally
            {
                _cancellationSource?.Dispose();
                _cancellationSource = null;
            }
        }

        private bool IsOnSameSubnet(IPAddress ip1, IPAddress ip2)
        {
            try
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
            catch (Exception ex)
            {
                _logger.LogError($"Subnet check failed: {ex.Message}");
                return false;
            }
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

        public async Task AddRouteAsync(string targetNetwork, string gatewayIp)
        {
            try
            {
                if (string.IsNullOrEmpty(targetNetwork) || string.IsNullOrEmpty(gatewayIp))
                {
                    throw new ArgumentException("Target network and gateway IP are required");
                }

                _logger.LogDebug($"Adding route: {targetNetwork} via {gatewayIp}");

                var startInfo = new ProcessStartInfo
                {
                    FileName = "route",
                    Arguments = $"add {targetNetwork} mask 255.255.255.0 {gatewayIp}",
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
                        _logger.LogInfo($"Route added successfully: {targetNetwork} via {gatewayIp}");
                    }
                    else
                    {
                        throw new Exception($"Route command failed with exit code: {process.ExitCode}");
                    }
                }
                else
                {
                    throw new Exception("Failed to start route command");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error adding route: {ex.Message}");
                throw;
            }
        }
    }
}