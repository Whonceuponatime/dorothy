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
        private bool _isAttackRunning;
        private CancellationTokenSource? _cancellationSource;
        private CancellationTokenSource? _gatewayResolutionCts;
        private Socket? _socket;
        private string? _attackType;
        public string SourceIp { get; private set; }
        public byte[] SourceMac { get; private set; }
        public string GatewayIp { get; private set; }
        public byte[] GatewayMac { get; private set; }
        public byte[] SubnetMask { get; private set; }
        public bool EnableLogging { get; set; }
        public string TargetIp { get; private set; } = string.Empty;
        public event EventHandler<PacketEventArgs>? PacketSent;
        public AttackLogger Logger => _logger;

        protected virtual void OnPacketSent(byte[] packet, IPAddress sourceIp, IPAddress destinationIp, int port)
        {
            PacketSent?.Invoke(this, new PacketEventArgs(packet, sourceIp, destinationIp, port));
        }

        public NetworkStorm(AttackLogger logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            SourceIp = string.Empty;
            SourceMac = Array.Empty<byte>();
            GatewayIp = string.Empty;
            GatewayMac = Array.Empty<byte>();
            SubnetMask = new byte[] { 255, 255, 255, 0 }; // Default /24 subnet mask
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
                OnPacketSent(
                    packet,
                    IPAddress.Parse(ipHeader.SourceAddress.ToString()),
                    IPAddress.Parse(ipHeader.DestinationAddress.ToString()),
                    tcpHeader?.DestinationPort ?? 0
                );
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

        public void SetSourceInfo(string sourceIp, byte[] sourceMac, byte[] subnetMask)
        {
            SourceIp = sourceIp;
            SourceMac = sourceMac;
            SubnetMask = subnetMask ?? new byte[] { 255, 255, 255, 0 };
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
                    // Only attempt resolution if SourceIp is set (NIC selected)
                    if (IPAddress.TryParse(gatewayIp, out var gatewayIpObj) && 
                        !string.IsNullOrEmpty(SourceIp) && 
                        IPAddress.TryParse(SourceIp, out var sourceIpObj))
                    {
                        // Only try to resolve gateway MAC if gateway is on the same subnet as source IP
                        // If it's on a different subnet, we can't resolve it via ARP anyway
                        if (IsOnSameSubnet(sourceIpObj, gatewayIpObj))
                    {
                        var gatewayMac = await GetMacAddressAsync(gatewayIp);
                        if (gatewayMac.Length > 0)
                        {
                            GatewayMac = gatewayMac;
                                _logger.LogInfo($"✅ Gateway MAC resolved: {BitConverter.ToString(gatewayMac).Replace("-", ":")}");
                        }
                            else
                            {
                                // Don't log as error - MAC resolution will be attempted when needed
                                _logger.LogInfo($"Gateway MAC not yet resolved for {gatewayIp}. Will attempt resolution when needed.");
                            }
                        }
                        else
                        {
                            // Gateway is on different subnet - can't resolve via ARP from this source IP
                            // This is normal for multi-NIC setups, will be resolved when actually needed
                            _logger.LogInfo($"Gateway {gatewayIp} is on different subnet from source {SourceIp}. MAC will be resolved when needed for attacks.");
                        }
                    }
                    else if (string.IsNullOrEmpty(SourceIp))
                    {
                        // Source IP not set yet - defer resolution
                        _logger.LogInfo($"Gateway {gatewayIp} set. MAC resolution will be attempted after NIC selection.");
                    }
                }
                catch (OperationCanceledException)
                {
                    // Ignore cancellation
                }
                catch (Exception ex)
                {
                    // Don't log as error - this is expected in multi-NIC scenarios
                    _logger.LogInfo($"Gateway MAC resolution deferred: {ex.Message}");
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
                        _logger.LogInfo($"Using gateway MAC for routed target {ipAddress}: {BitConverter.ToString(GatewayMac).Replace("-", ":")}");
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
                            // Don't log as error - this might be normal in multi-NIC scenarios
                            // The gateway might not be reachable from the current source IP
                            _logger.LogWarning($"Could not resolve gateway MAC address for {GatewayIp} from source {SourceIp}. " +
                                              $"This may be normal if using multiple NICs. MAC will be resolved when needed or use fallback mode.");
                            return Array.Empty<byte>();
                        }

                        GatewayMac = macAddr;
                        _logger.LogInfo($"✅ Using gateway MAC for routed target {ipAddress}: {BitConverter.ToString(macAddr).Replace("-", ":")}");
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
                _logger.LogError($"Failed to resolve MAC address: {ex.Message}");
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
                    _logger.LogError("Gateway MAC address is required for cross-subnet communication");
                    throw new InvalidOperationException("Gateway MAC address is required for cross-subnet communication");
                }
                        _logger.LogInfo($"🌐 Using gateway MAC for external target: {BitConverter.ToString(GatewayMac).Replace("-", ":")}");
                destinationMac = GatewayMac;
            }
            else
            {
                // For same subnet, try to get target's MAC
                destinationMac = await GetMacAddressAsync(targetIp);
                if (destinationMac.Length == 0)
                {
                    _logger.LogError("Could not resolve target MAC address for local subnet target");
                    throw new InvalidOperationException("Could not resolve target MAC address for local subnet target");
                }
                _logger.LogInfo($"📍 Using target MAC for local target: {BitConverter.ToString(destinationMac).Replace("-", ":")}");
            }

            // Calculate bytes per second: megabits -> bits -> bytes
            // 1 Mbps = 1,000,000 bits per second
            // 8 bits = 1 byte
            // Calculate exact bytes per second without overhead multiplication
            // The packet size calculation will account for headers separately
            long bytesPerSecond = (long)(megabitsPerSecond * 1_000_000L / 8.0);

            return new PacketParameters
            {
                SourceMac = SourceMac,
                DestinationMac = destinationMac,
                SourceIp = sourceIpObj,
                DestinationIp = targetIpObj,
                SourcePort = Random.Shared.Next(49152, 65535),
                DestinationPort = targetPort,
                BytesPerSecond = bytesPerSecond,
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

                // Run the attack in a background task to prevent UI freezing
                await Task.Run(async () => {
                    try
                    {
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

                        // Attack details are logged by AttackLogger.StartAttack() in MainWindow.xaml.cs
                        // No need to duplicate the logging here

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

                            case AttackType.TcpSynFlood:
                                if (!IsOnSameSubnet(sourceIpObj, targetIpObj))
                                {
                                    _logger.LogInfo("Target is on different subnet - Using routed TCP flood attack");
                                    using (var tcpFlood = new TcpFloodRouted(packetParams, _cancellationSource.Token))
                                    {
                                        await tcpFlood.StartAsync();
                                    }
                                }
                                else
                                {
                                    using (var tcpFlood = new TcpFlood(packetParams, _cancellationSource.Token))
                                    {
                                        await tcpFlood.StartAsync();
                                    }
                                }
                                break;

                            default:
                                throw new ArgumentException($"Unsupported attack type: {attackType}");
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError($"Attack task failed: {ex.Message}");
                        throw;
                    }
                }, _cancellationSource.Token);
            }
            catch (Exception ex)
            {
                _isAttackRunning = false;
                _logger.LogError($"Attack failed: {ex.Message}");
                // Don't rethrow to prevent UI freeze
                await StopAttackAsync();
            }
        }

        public async Task StopAttackAsync(long packetsSent = 0)
        {
            if (!_isAttackRunning)
            {
                return;
            }

            try
            {
                _cancellationSource?.Cancel();
                _isAttackRunning = false;
                
                // Log comprehensive stop information
                _logger.StopAttack(packetsSent);
                
                // Then log the specific attack stop message
                if (!string.IsNullOrEmpty(_attackType))
                {
                    _logger.LogInfo($"Stopped {_attackType} attack");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to stop attack: {ex.Message}");
                throw;
            }
        }

        private bool IsOnSameSubnet(IPAddress ip1, IPAddress ip2)
        {
            try
            {
                byte[] subnet = SubnetMask;
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

        private IPAddress? CalculateDefaultGateway(string sourceIp)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(sourceIp) || !IPAddress.TryParse(sourceIp, out var sourceIpAddress))
                {
                    return null;
                }

                var bytes = sourceIpAddress.GetAddressBytes();
                bytes[3] = 1; // Set last octet to 1 (x.x.x.x.1)
                return new IPAddress(bytes);
            }
            catch
            {
                return null;
            }
        }

        public IPAddress? GetDefaultGatewayWithFallback(string sourceIp)
        {
            // Try to get system default gateway first
            var systemGateway = GetDefaultGateway();
            if (systemGateway != null)
            {
                return systemGateway;
            }

            // Fallback to calculated default (x.x.x.x.1)
            return CalculateDefaultGateway(sourceIp);
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

        public async Task StartEthernetAttackAsync(string targetIp, int targetPort, long megabitsPerSecond, EthernetFlood.EthernetPacketType packetType, bool useIPv6 = false)
        {
            if (_isAttackRunning)
            {
                _logger.LogWarning("Attack already in progress");
                return;
            }

            try
            {
                _cancellationSource = new CancellationTokenSource();
                _isAttackRunning = true;

                await Task.Run(async () =>
                {
                    try
                    {
                        var packetParams = await CreatePacketParameters(targetIp, targetPort, megabitsPerSecond);
                        using var flood = new EthernetFlood(packetParams, packetType, _cancellationSource.Token, useIPv6);
                        await flood.StartAsync();
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError($"Ethernet attack failed: {ex.Message}");
                        throw;
                    }
                }, _cancellationSource.Token);
            }
            catch (Exception ex)
            {
                _isAttackRunning = false;
                _logger.LogError($"Failed to start Ethernet attack: {ex.Message}");
                await StopAttackAsync();
            }
        }
    }
}