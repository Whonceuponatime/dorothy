using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Controls;
using NLog;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using PacketProtocolType = PacketDotNet.ProtocolType;
using SocketsProtocolType = System.Net.Sockets.ProtocolType;
using System.Runtime.InteropServices;

namespace Dorothy.Models
{
    public class NetworkStorm : IDisposable
    {
        private string _sourceIp = string.Empty;
        private byte[] _sourceMac = Array.Empty<byte>();
        private bool _isAttackRunning = false;
        private readonly TextBox _logArea;
        private CancellationTokenSource? _cancellationSource;

        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();

        public bool IsAttackRunning => _isAttackRunning;

        public NetworkStorm(TextBox logArea)
        {
            _logArea = logArea ?? throw new ArgumentNullException(nameof(logArea));
        }

        public void SetSourceIp(string sourceIp)
        {
            if (string.IsNullOrWhiteSpace(sourceIp))
                throw new ArgumentException("Source IP cannot be null or empty.", nameof(sourceIp));

            _sourceIp = sourceIp;
            Logger.Info($"Source IP set to {_sourceIp}");
        }

        public void SetSourceMac(byte[] sourceMac)
        {
            if (sourceMac == null || sourceMac.Length != 6)
                throw new ArgumentException("Source MAC must be a 6-byte array.", nameof(sourceMac));

            _sourceMac = sourceMac;
            Logger.Info($"Source MAC set to {BitConverter.ToString(_sourceMac).Replace("-", ":")}");
        }

        public async Task StartAttackAsync(AttackType attackType, string targetIp, int targetPort, long megabitsPerSecond)
        {
            if (_isAttackRunning)
            {
                Log("Attack already in progress.");
                return;
            }

            _cancellationSource = new CancellationTokenSource();
            _isAttackRunning = true;

            Log("Starting attack...");
            try
            {
                string targetMacString = await GetMacAddressAsync(targetIp, _sourceIp);
                byte[] targetMac = ParseMacAddress(targetMacString);

                switch (attackType)
                {
                    case AttackType.UdpFlood:
                        using (var udpFlood = new UdpFlood(
                            _sourceIp,
                            _sourceMac,
                            targetIp,
                            targetMac,
                            targetPort,
                            megabitsPerSecond * 125_000, // Convert Mbps to bytes per second
                            _cancellationSource.Token))
                        {
                            await udpFlood.StartAsync();
                        }
                        break;
                    case AttackType.IcmpFlood:
                        using (var icmpFlood = new IcmpFlood(
                            _sourceIp,
                            _sourceMac,
                            targetIp,
                            targetMac,
                            megabitsPerSecond * 125_000,
                            _cancellationSource.Token))
                        {
                            await icmpFlood.StartAsync();
                        }
                        break;
                    case AttackType.TcpSynFlood:
                        using (var tcpFlood = new TcpFlood(
                            _sourceIp,
                            _sourceMac,
                            targetIp,
                            targetMac,
                            targetPort,
                            megabitsPerSecond * 125_000,
                            _cancellationSource.Token))
                        {
                            await tcpFlood.StartAsync();
                        }
                        break;
                    default:
                        throw new ArgumentException($"Unsupported attack type: {attackType}", nameof(attackType));
                }
            }
            catch (Exception ex)
            {
                Log($"Error during attack: {ex.Message}");
                Logger.Error(ex, "Attack failed.");
            }
            finally
            {
                _isAttackRunning = false;
                _cancellationSource.Dispose();
                Log("Attack finished.");
            }
        }

        public async Task StopAttackAsync()
        {
            if (!_isAttackRunning)
            {
                Log("No attack is running.");
                return;
            }

            _cancellationSource?.Cancel();

            // Allow some time for the attack to stop gracefully
            await Task.Delay(500);

            _cancellationSource?.Dispose();
            _isAttackRunning = false;

            Log("Attack has been stopped.");
        }

        private async Task<string> GetMacAddressAsync(string targetIp, string sourceIp)
        {
            try
            {
                // Ensure the target is reachable by pinging
                bool pingable = await PingHostAsync(targetIp);
                if (!pingable)
                {
                    throw new Exception($"Target IP {targetIp} is not reachable.");
                }

                // Resolve source IP to interface
                NetworkInterface? sourceInterface = NetworkInterface.GetAllNetworkInterfaces()
                    .FirstOrDefault(ni =>
                    {
                        var ipv4Props = ni.GetIPProperties().UnicastAddresses
                            .FirstOrDefault(ua => ua.Address.ToString() == sourceIp);
                        return ipv4Props != null && ni.OperationalStatus == OperationalStatus.Up;
                    });

                if (sourceInterface == null)
                {
                    throw new Exception($"No network interface found with source IP {sourceIp}.");
                }

                // Convert IP addresses to integers (network byte order)
                IPAddress srcIp = IPAddress.Parse(sourceIp);
                IPAddress dstIp = IPAddress.Parse(targetIp);
                uint srcIpInt = BitConverter.ToUInt32(srcIp.GetAddressBytes().Reverse().ToArray(), 0);
                uint dstIpInt = BitConverter.ToUInt32(dstIp.GetAddressBytes().Reverse().ToArray(), 0);

                byte[] macAddr = new byte[6];
                int macAddrLen = macAddr.Length;

                int result = SendARP((int)dstIpInt, (int)srcIpInt, macAddr, ref macAddrLen);
                if (result != 0)
                {
                    throw new Exception($"SendARP failed with error code {result}.");
                }

                // Convert MAC address bytes to string format
                string macAddress = BitConverter.ToString(macAddr, 0, macAddrLen).Replace("-", ":");
                return macAddress;
            }
            catch (Exception ex)
            {
                Logger.Error(ex, $"Failed to get MAC address for IP {targetIp}.");
                throw;
            }
        }

        private byte[] ParseMacAddress(string macString)
        {
            try
            {
                return macString.Split(':').Select(hex => Convert.ToByte(hex, 16)).ToArray();
            }
            catch (Exception ex)
            {
                Logger.Error(ex, $"Failed to parse MAC address from string {macString}.");
                throw new Exception("Invalid MAC address format.");
            }
        }

        private async Task<bool> PingHostAsync(string host)
        {
            using (var ping = new Ping())
            {
                try
                {
                    PingReply reply = await ping.SendPingAsync(host, 1000);
                    return reply.Status == IPStatus.Success;
                }
                catch (PingException ex)
                {
                    Logger.Error(ex, $"Ping to {host} failed.");
                    return false;
                }
            }
        }

        public void Log(string message)
        {
            _logArea.Dispatcher.Invoke(() =>
            {
                _logArea.AppendText($"{DateTime.Now}: {message}\n");
                _logArea.ScrollToEnd();
            });
        }

        public void Dispose()
        {
            _cancellationSource?.Dispose();
        }

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern int SendARP(int DestIP, int SrcIP, byte[] pMacAddr, ref int PhyAddrLen);
    }
}
