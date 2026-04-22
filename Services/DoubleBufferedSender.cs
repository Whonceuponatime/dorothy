using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using NLog;
using SharpPcap;
using SharpPcap.LibPcap;

namespace Dorothy.Services
{
    public sealed class DoubleBufferedSender : IDisposable
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();

        private readonly LibPcapLiveDevice _device;
        private readonly int _capacity;
        private readonly int _flushBytes;
        private readonly int _flushPackets;
        private readonly string _tag;

        private SendQueue _active;
        private int _packetsInActive;
        private Task _flushTask = Task.CompletedTask;
        private bool _disposed;

        private long _lastFlushBytes;
        private long _lastFlushMicros;

        public long LastFlushTransmittedBytes => Interlocked.Read(ref _lastFlushBytes);
        public long LastFlushMicros           => Interlocked.Read(ref _lastFlushMicros);

        public DoubleBufferedSender(
            LibPcapLiveDevice device,
            int capacityBytes,
            int flushBytes,
            int flushPackets,
            string tag)
        {
            _device       = device ?? throw new ArgumentNullException(nameof(device));
            _capacity     = capacityBytes;
            _flushBytes   = flushBytes;
            _flushPackets = flushPackets;
            _tag          = tag ?? "SEND";
            _active       = new SendQueue(capacityBytes);
        }

        /// <summary>Add a packet. Returns true if a background flush was started.</summary>
        public bool AddPacket(byte[] packet)
        {
            if (_active.CurrentLength + packet.Length + 16 > _capacity)
            {
                Swap();
            }

            _active.Add(packet);
            _packetsInActive++;

            if (_active.CurrentLength >= _flushBytes || _packetsInActive >= _flushPackets)
            {
                Swap();
                return true;
            }
            return false;
        }

        public void ForceFlush()
        {
            if (_packetsInActive == 0) return;
            Swap();
        }

        public void WaitForPendingFlush()
        {
            try { _flushTask.Wait(); } catch { }
        }

        private void Swap()
        {
            // Producer blocks here only if background transmit is still running.
            // With correct sizing this is near-instant.
            try { _flushTask.Wait(); } catch { }

            var toSend = _active;
            _active = new SendQueue(_capacity);
            _packetsInActive = 0;

            _flushTask = Task.Run(() =>
            {
                try
                {
                    var sw = Stopwatch.StartNew();
                    long inBytes = toSend.CurrentLength;
                    int transmitted = toSend.Transmit(_device, SendQueueTransmitModes.Normal);
                    sw.Stop();
                    double flushMs = sw.Elapsed.TotalMilliseconds;
                    double effMbps = flushMs > 0 ? (transmitted * 8.0) / (flushMs * 1000.0) : 0.0;
                    Interlocked.Exchange(ref _lastFlushBytes, transmitted);
                    Interlocked.Exchange(ref _lastFlushMicros, (long)(flushMs * 1000));
                    Logger.Info(
                        $"[{_tag}][FLUSH] in_bytes={inBytes} transmitted={transmitted} " +
                        $"flush_ms={flushMs:F2} effective_mbps={effMbps:F2}");
                }
                catch (Exception ex)
                {
                    Logger.Warn(ex, $"[{_tag}][FLUSH] transmit failed");
                }
                finally
                {
                    try { toSend.Dispose(); } catch { }
                }
            });
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;

            try { ForceFlush(); } catch { }
            try { _flushTask.Wait(TimeSpan.FromSeconds(10)); } catch { }
            try { _active.Dispose(); } catch { }
        }
    }
}
