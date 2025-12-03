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
    /// <summary>
    /// UDP flood attack with NMEA 0183 navigation data payload.
    /// Generates realistic NMEA sentences (e.g., $GPGGA, $GPRMC) for navigation data testing.
    /// </summary>
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

        /// <summary>
        /// Generates a realistic NMEA 0183 sentence.
        /// Common sentence types: GPGGA (Global Positioning System Fix Data),
        /// GPRMC (Recommended Minimum Specific GPS/Transit Data), GPGLL (Geographic Position - Latitude/Longitude)
        /// </summary>
        private string GenerateNmeaSentence()
        {
            var sentenceType = _random.Next(0, 3) switch
            {
                0 => "GPGGA",
                1 => "GPRMC",
                _ => "GPGLL"
            };

            // Generate realistic-looking NMEA data
            var utcTime = DateTime.UtcNow.ToString("HHmmss.fff");
            var latitude = $"{_random.Next(0, 90):D2}{_random.Next(0, 60):D2}.{_random.Next(0, 9999):D4}";
            var latDir = _random.Next(0, 2) == 0 ? "N" : "S";
            var longitude = $"{_random.Next(0, 180):D3}{_random.Next(0, 60):D2}.{_random.Next(0, 9999):D4}";
            var lonDir = _random.Next(0, 2) == 0 ? "E" : "W";
            var quality = _random.Next(1, 9); // GPS quality indicator (1-8)
            var satellites = _random.Next(4, 12); // Number of satellites
            var hdop = $"{_random.Next(0, 20):D1}.{_random.Next(0, 9):D1}"; // Horizontal dilution of precision
            var altitude = $"{_random.Next(0, 10000):D1}.{_random.Next(0, 9):D1}";
            var speed = $"{_random.Next(0, 50):D1}.{_random.Next(0, 9):D1}"; // Knots
            var course = $"{_random.Next(0, 360):D3}.{_random.Next(0, 9):D1}"; // Degrees
            var date = DateTime.UtcNow.ToString("ddMMyy");

            return sentenceType switch
            {
                "GPGGA" => $"$GPGGA,{utcTime},{latitude},{latDir},{longitude},{lonDir},{quality},{satellites},{hdop},{altitude},M,{altitude},M,,*{CalculateNmeaChecksum($"GPGGA,{utcTime},{latitude},{latDir},{longitude},{lonDir},{quality},{satellites},{hdop},{altitude},M,{altitude},M,,"):X2}",
                "GPRMC" => $"$GPRMC,{utcTime},A,{latitude},{latDir},{longitude},{lonDir},{speed},{course},{date},,A*{CalculateNmeaChecksum($"GPRMC,{utcTime},A,{latitude},{latDir},{longitude},{lonDir},{speed},{course},{date},,A"):X2}",
                "GPGLL" => $"$GPGLL,{latitude},{latDir},{longitude},{lonDir},{utcTime},A*{CalculateNmeaChecksum($"GPGLL,{latitude},{latDir},{longitude},{lonDir},{utcTime},A"):X2}",
                _ => $"$GPGGA,{utcTime},{latitude},{latDir},{longitude},{lonDir},{quality},{satellites},{hdop},{altitude},M,{altitude},M,,*{CalculateNmeaChecksum($"GPGGA,{utcTime},{latitude},{latDir},{longitude},{lonDir},{quality},{satellites},{hdop},{altitude},M,{altitude},M,,"):X2}"
            };
        }

        /// <summary>
        /// Calculates NMEA 0183 checksum (XOR of all characters between $ and *)
        /// </summary>
        private byte CalculateNmeaChecksum(string sentence)
        {
            byte checksum = 0;
            foreach (char c in sentence)
            {
                checksum ^= (byte)c;
            }
            return checksum;
        }

        /// <summary>
        /// Generates NMEA payload. Can contain one or more sentences per datagram.
        /// </summary>
        private byte[] GenerateNmeaPayload(int maxSize = 1400)
        {
            var sentences = new System.Collections.Generic.List<string>();
            int totalLength = 0;

            // Add multiple sentences until we approach max size
            while (totalLength < maxSize - 100) // Leave some buffer
            {
                var sentence = GenerateNmeaSentence() + "\r\n"; // NMEA sentences end with CRLF
                if (totalLength + Encoding.ASCII.GetByteCount(sentence) > maxSize)
                    break;
                
                sentences.Add(sentence);
                totalLength += Encoding.ASCII.GetByteCount(sentence);
            }

            // If no sentences fit, generate at least one
            if (sentences.Count == 0)
            {
                sentences.Add(GenerateNmeaSentence() + "\r\n");
            }

            var payload = string.Join("", sentences);
            var payloadBytes = Encoding.ASCII.GetBytes(payload);

            // Pad to desired size if needed (optional - NMEA is typically variable length)
            if (payloadBytes.Length < maxSize)
            {
                var padded = new byte[maxSize];
                Array.Copy(payloadBytes, padded, payloadBytes.Length);
                // Fill remainder with spaces or nulls (NMEA doesn't require padding, but for flood testing we can pad)
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
                
                // For multicast, set socket options
                if (_isMulticast)
                {
                    // Set TTL to 1 for local network multicast
                    _socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, 1);
                    
                    // Join multicast group (optional, but helps with some network stacks)
                    var multicastIp = _params.DestinationIp;
                    if (multicastIp.AddressFamily == AddressFamily.InterNetwork)
                    {
                        _socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.AddMembership, 
                            new MulticastOption(multicastIp));
                    }
                }

                byte[] udpHeader = new byte[8];  // UDP header size
                
                // Account for full Ethernet frame: Ethernet header (14) + IP header (20) + UDP header (8) + payload + FCS (4)
                // Raw sockets send at Layer 3, OS adds Ethernet frame
                // For NMEA, typical payload is 50-200 bytes per sentence, but we'll use variable size
                // Use a fixed typical size for initial rate calculation, but track actual size per packet
                int typicalPayloadSize = 200; // Typical NMEA datagram size
                int typicalPacketSize = 14 + 20 + udpHeader.Length + typicalPayloadSize + 4; // Ethernet (14) + IP (20) + UDP (8) + payload + FCS (4)

                await Task.Run(() =>
                {
                    var stopwatch = Stopwatch.StartNew();
                    var endpoint = new IPEndPoint(_params.DestinationIp, _params.DestinationPort);
                    
                    // Byte-budget rate control: track bytes sent vs time elapsed
                    long bytesSent = 0;
                    long targetBytesPerSecond = _params.BytesPerSecond;
                    double targetMbps = targetBytesPerSecond * 8.0 / 1_000_000;
                    
                    // Rate measurement for logging/UI only (not used for timing)
                    var measurementStartTime = stopwatch.ElapsedTicks;
                    long measurementStartBytes = 0;
                    const int measurementWindowMs = 500; // Measure every 500ms
                    double smoothedActualMbps = 0;
                    const double smoothingAlpha = 0.3; // Exponential smoothing factor
                    
                    // Determine if low rate (for Windows-friendly waiting)
                    bool isLowRate = targetMbps < 5.0;
                    int sleepCounter = 0; // For mixing sleep with spin-wait at low rates

                    stopwatch.Start();

                    while (!_cancellationToken.IsCancellationRequested)
                    {
                        // Check cancellation at the start of each iteration
                        if (_cancellationToken.IsCancellationRequested)
                        {
                            break;
                        }
                        
                        try
                        {
                            // Generate NMEA payload
                            var payload = GenerateNmeaPayload(typicalPayloadSize);
                            int actualPayloadSize = payload.Length;
                            // Calculate actual wire packet size: Ethernet (14) + IP (20) + UDP (8) + payload + FCS (4)
                            int actualPacketSize = 14 + 20 + udpHeader.Length + actualPayloadSize + 4;

                            // Calculate how many bytes we're "allowed" to have sent so far
                            double elapsedSeconds = stopwatch.ElapsedTicks / (double)Stopwatch.Frequency;
                            long allowedBytes = (long)(elapsedSeconds * targetBytesPerSecond);
                            
                            // If we're behind budget, send packets (small burst)
                            if (bytesSent < allowedBytes)
                            {
                                // Calculate how many packets we can send to catch up (but limit burst size)
                                // Use typical packet size for burst calculation to avoid over-sending
                                long bytesBehind = allowedBytes - bytesSent;
                                int packetsToSend = Math.Min((int)(bytesBehind / typicalPacketSize) + 1, 5); // Max 5 packets per iteration
                                
                                for (int i = 0; i < packetsToSend && bytesSent < allowedBytes && !_cancellationToken.IsCancellationRequested; i++)
                                {
                                    // Regenerate payload for each packet (realistic variation)
                                    payload = GenerateNmeaPayload(typicalPayloadSize);
                                    actualPayloadSize = payload.Length;
                                    // Recalculate actual packet size for this specific packet
                                    actualPacketSize = 14 + 20 + udpHeader.Length + actualPayloadSize + 4;

                                    // Create UDP header
                                    BitConverter.GetBytes((ushort)_params.SourcePort).CopyTo(udpHeader, 0);
                                    BitConverter.GetBytes((ushort)_params.DestinationPort).CopyTo(udpHeader, 2);
                                    BitConverter.GetBytes((ushort)(8 + actualPayloadSize)).CopyTo(udpHeader, 4); // Length
                                    BitConverter.GetBytes((ushort)0).CopyTo(udpHeader, 6); // Checksum (0 = not calculated)

                                    // Combine header and payload
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
                                // We're at or above budget - wait briefly
                                // Windows-friendly waiting: spin-wait at high rates, mix sleep+spin at low rates
                                if (isLowRate && sleepCounter++ % 10 == 0)
                                {
                                    // At low rates, sleep occasionally to avoid pegging CPU core
                                    Thread.Sleep(0); // Yield to other threads
                                }
                                else
                                {
                                    // Short spin-wait for precision
                                    Thread.SpinWait(10);
                                }
                            }

                            // Rate measurement for logging/UI (time-based window, smoothed)
                            long currentTicks = stopwatch.ElapsedTicks;
                            double elapsedSinceMeasurement = (currentTicks - measurementStartTime) / (double)Stopwatch.Frequency;
                            
                            if (elapsedSinceMeasurement >= measurementWindowMs / 1000.0)
                            {
                                long bytesInWindow = bytesSent - measurementStartBytes;
                                double actualMbps = (bytesInWindow * 8.0) / (elapsedSinceMeasurement * 1_000_000);
                                
                                // Exponential smoothing to reduce Windows jitter
                                if (smoothedActualMbps == 0)
                                    smoothedActualMbps = actualMbps;
                                else
                                    smoothedActualMbps = (smoothingAlpha * actualMbps) + ((1.0 - smoothingAlpha) * smoothedActualMbps);
                                
                                Logger.Info($"NMEA 0183 UDP rate: actual={smoothedActualMbps:F2} Mbps, target={targetMbps:F2} Mbps, bytesSent={bytesSent}, allowed={allowedBytes}");
                                
                                // Reset measurement window
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
                
                // Ensure socket is closed when task completes or is cancelled
                if (_cancellationToken.IsCancellationRequested)
                {
                    Logger.Info("NMEA 0183 attack cancelled, closing socket.");
                }
            }
            catch (OperationCanceledException)
            {
                Logger.Info("NMEA 0183 attack was cancelled.");
                // Don't rethrow cancellation exceptions
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "NMEA 0183 UDP Flood attack failed.");
                throw;
            }
            finally
            {
                // Ensure socket is closed even on exception
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
                    // Leave multicast group
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

