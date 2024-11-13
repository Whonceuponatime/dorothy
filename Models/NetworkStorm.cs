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
        private readonly TextBox _logArea;
        private readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        private bool _isAttackRunning;
        private CancellationTokenSource? _cancellationSource;
        private string _sourceIp = string.Empty;
        private byte[] _sourceMac = new byte[6];
        public bool EnableLogging { get; set; }

        public NetworkStorm(TextBox logArea)
        {
            _logArea = logArea ?? throw new ArgumentNullException(nameof(logArea));
        }

        public void SetSourceInfo(string sourceIp, byte[] sourceMac)
        {
            _sourceIp = sourceIp;
            _sourceMac = sourceMac;
        }

        private void Log(string message)
        {
            _logArea.Dispatcher.Invoke(() =>
            {
                _logArea.AppendText($"{DateTime.Now}: {message}\n");
                _logArea.ScrollToEnd();
            });
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
                byte[] targetMac = await GetMacAddressAsync(targetIp, _sourceIp);

                switch (attackType)
                {
                    case AttackType.UdpFlood:
                        using (var udpFlood = new UdpFlood(
                            _sourceIp,
                            _sourceMac,
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
                    case AttackType.SynFlood:
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
                    case AttackType.HttpFlood:
                        Log("HTTP Flood attack not implemented yet.");
                        break;
                    default:
                        Log("Unknown Attack Type.");
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
                _cancellationSource?.Dispose();
            }
        }

        public async Task StopAttackAsync()
        {
            if (!_isAttackRunning)
            {
                Log("No attack is currently running.");
                return;
            }

            try
            {
                Log("Stopping attack...");
                _cancellationSource?.Cancel();
                _isAttackRunning = false;
                await Task.CompletedTask;
                Log("Attack stop signal sent.");
            }
            finally
            {
                _cancellationSource?.Dispose();
                _cancellationSource = null;
            }
        }

        private async Task<byte[]> GetMacAddressAsync(string targetIp, string sourceIp)
        {
            return await Task.Run(() =>
            {
                try
                {
                    var targetAddr = BitConverter.ToInt32(IPAddress.Parse(targetIp).GetAddressBytes(), 0);
                    var srcAddr = BitConverter.ToInt32(IPAddress.Parse(sourceIp).GetAddressBytes(), 0);
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
                    Logger.Error(ex, "Failed to get MAC address.");
                    throw;
                }
            });
        }

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern int SendARP(int destIp, int srcIp, byte[] macAddr, ref uint macAddrLen);
    }
}
