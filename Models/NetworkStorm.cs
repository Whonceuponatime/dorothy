using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using NLog;
using System.Net.NetworkInformation;
using System.Linq;

namespace Dorothy.Models
{
    public class NetworkStorm : IDisposable
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        private CancellationTokenSource _cancellationSource;
        private readonly List<Task> _activeTasks;
        private readonly object _lockObject = new();
        private TextBox? _logArea;
        private string? _sourceIp;
        private byte[]? _sourceMac;
        private AttackLogger? _attackLogger;
        private volatile bool _isAttackRunning;

        public NetworkStorm()
        {
            _cancellationSource = new CancellationTokenSource();
            _activeTasks = new List<Task>();
            _isAttackRunning = false;
        }

        public bool IsAttackRunning => _isAttackRunning;

        public void SetLogArea(TextBox logArea)
        {
            _logArea = logArea ?? throw new ArgumentNullException(nameof(logArea));
        }

        public void SetSourceIp(string ip)
        {
            if (string.IsNullOrWhiteSpace(ip))
                throw new ArgumentException("IP address cannot be empty", nameof(ip));
            _sourceIp = ip;
        }

        public void SetSourceMac(byte[] mac)
        {
            if (mac == null || mac.Length != 6)
                throw new ArgumentException("Invalid MAC address", nameof(mac));
            _sourceMac = mac;
        }

        public async Task StartUdpFloodAsync(string targetIp, int targetPort, long bytesPerSecond)
        {
            if (string.IsNullOrEmpty(_sourceIp))
                throw new InvalidOperationException("Source IP not set");
            if (_sourceMac == null)
                throw new InvalidOperationException("Source MAC not set");
            if (string.IsNullOrEmpty(targetIp))
                throw new ArgumentException("Target IP cannot be empty", nameof(targetIp));
            if (targetPort <= 0 || targetPort > 65535)
                throw new ArgumentException("Invalid port number", nameof(targetPort));
            if (bytesPerSecond <= 0)
                throw new ArgumentException("Bytes per second must be positive", nameof(bytesPerSecond));

            if (_isAttackRunning)
            {
                Log("Attack already in progress");
                return;
            }

            try
            {
                _isAttackRunning = true;
                var targetMac = await GetMacAddressAsync(targetIp);
                
                _attackLogger = new AttackLogger(
                    "UDP", 
                    targetIp, 
                    targetMac, 
                    _sourceIp,
                    BytesToMacString(_sourceMac), 
                    bytesPerSecond, 
                    _logArea
                );

                using var udpFlood = new UdpFlood(_sourceIp!, targetIp, targetPort, 
                    bytesPerSecond * 8 / 1_000_000, _cancellationSource.Token);
                var floodTask = Task.Run(async () =>
                {
                    try
                    {
                        await udpFlood.StartAsync();
                        while (!_cancellationSource.Token.IsCancellationRequested)
                        {
                            var stats = udpFlood.GetStats();
                            LogAttackStats("UDP", targetIp, stats.currentMbps, 
                                         stats.currentMbps, 
                                         stats.packetsSent, stats.packetsSent * UdpFlood.PACKET_SIZE);
                            await Task.Delay(1000, _cancellationSource.Token);
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        Log("Attack cancelled");
                    }
                    catch (Exception ex)
                    {
                        Logger.Error(ex, "Error in UDP flood task");
                        Log($"Error: {ex.Message}");
                        _isAttackRunning = false;
                    }
                    finally
                    {
                        udpFlood.Stop();
                    }
                }, _cancellationSource.Token);

                lock (_lockObject)
                {
                    _activeTasks.Add(floodTask);
                }
            }
            catch (Exception)
            {
                _isAttackRunning = false;
                throw;
            }
        }

        public async Task StartIcmpFloodAsync(string targetIp, long bytesPerSecond)
        {
            if (_isAttackRunning)
            {
                Log("Attack already in progress");
                return;
            }

            try
            {
                _isAttackRunning = true;
                var targetMac = await GetMacAddressAsync(targetIp);
                
                _attackLogger = new AttackLogger(
                    "ICMP", 
                    targetIp, 
                    targetMac, 
                    _sourceIp,
                    BytesToMacString(_sourceMac), 
                    bytesPerSecond, 
                    _logArea
                );

                using var icmpFlood = new IcmpFlood(targetIp, bytesPerSecond);
                var floodTask = Task.Run(async () =>
                {
                    try
                    {
                        await icmpFlood.StartAsync();
                        while (!_cancellationSource.Token.IsCancellationRequested)
                        {
                            icmpFlood.UpdateStats(this);
                            await Task.Delay(1000, _cancellationSource.Token);
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        Log("Attack cancelled");
                    }
                    catch (Exception ex)
                    {
                        Logger.Error(ex, "Error in ICMP flood task");
                        Log($"Error: {ex.Message}");
                        _isAttackRunning = false;
                        throw;
                    }
                }, _cancellationSource.Token);

                lock (_lockObject)
                {
                    _activeTasks.Add(floodTask);
                }
            }
            catch (Exception)
            {
                _isAttackRunning = false;
                throw;
            }
        }

        public void LogAttackStats(string attackType, string targetIp, double currentRate, 
                                 double targetRate, long totalPackets, double totalDataSent)
        {
            _attackLogger?.LogStats(currentRate, targetRate, totalPackets, totalDataSent);
        }

        private async Task<string> GetMacAddressAsync(string ipAddress)
        {
            try
            {
                using var ping = new Ping();
                await ping.SendPingAsync(ipAddress, 1000);
                
                var arp = await Task.Run(() =>
                {
                    var process = new System.Diagnostics.Process
                    {
                        StartInfo = new System.Diagnostics.ProcessStartInfo
                        {
                            FileName = "arp",
                            Arguments = $"-a {ipAddress}",
                            UseShellExecute = false,
                            RedirectStandardOutput = true,
                            CreateNoWindow = true
                        }
                    };
                    process.Start();
                    var output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();
                    return output;
                });

                var macAddress = ParseArpOutput(arp, ipAddress);
                return macAddress ?? "00:00:00:00:00:00";
            }
            catch (Exception ex)
            {
                Logger.Warn(ex, "Failed to get MAC address");
                return "00:00:00:00:00:00";
            }
        }

        private string ParseArpOutput(string arpOutput, string targetIp)
        {
            var lines = arpOutput.Split('\n');
            foreach (var line in lines)
            {
                if (line.Contains(targetIp))
                {
                    var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 2)
                    {
                        return parts[1].Replace("-", ":");
                    }
                }
            }
            return null;
        }

        private string BytesToMacString(byte[] mac)
        {
            return mac == null ? "00:00:00:00:00:00" 
                : string.Join(":", Array.ConvertAll(mac, b => b.ToString("X2")));
        }

        private void Log(string message)
        {
            if (_logArea == null) return;

            Application.Current.Dispatcher.Invoke(() =>
            {
                _logArea.AppendText($"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} {message}\n");
                _logArea.ScrollToEnd();
            });
        }

        public async Task StopAttackAsync()
        {
            if (!_isAttackRunning) return;

            try
            {
                _isAttackRunning = false;
                
                lock (_lockObject)
                {
                    if (_activeTasks.Count > 0)
                    {
                        _cancellationSource.Cancel();
                        
                        foreach (var task in _activeTasks)
                        {
                            try 
                            {
                                if (!task.IsCompleted)
                                {
                                    task.Wait(100);
                                }
                            }
                            catch (Exception ex)
                            {
                                Logger.Warn(ex, "Error waiting for task to complete");
                            }
                        }
                        _activeTasks.Clear();
                    }
                }
                
                _cancellationSource = new CancellationTokenSource();
                
                _attackLogger?.LogStop();
                Log("Attack stopped");
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Error stopping attack");
                throw;
            }
        }

        public void Dispose()
        {
            _cancellationSource.Cancel();
            _cancellationSource.Dispose();
            
            lock (_lockObject)
            {
                _activeTasks.Clear();
            }

            GC.SuppressFinalize(this);
        }
    }
} 