using System;
using System.Linq;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using NLog;

namespace Dorothy.Services
{
    public enum ConnectivityState
    {
        Unknown,
        LocalOnly,           // Default gateway reachable, no internet anchors
        InternetReachable
    }

    /// <summary>
    /// Background pinger that classifies the host's connectivity as
    /// InternetReachable / LocalOnly / Unknown. Used by the NI tab to
    /// short-circuit probes targeting public IPs when the internet is
    /// down, and to surface a user-visible status chip in the toolbar.
    ///
    /// Runs ICMP echo against two anchors (Google + Cloudflare DNS) on
    /// a 30-second interval. Never awaits onto the UI thread; consumers
    /// hook StateChanged and dispatch as needed.
    /// </summary>
    public class ConnectivityMonitorService
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();

        private const int CheckIntervalSeconds = 30;
        private const int PingTimeoutMs        = 1500;
        private const string AnchorIp          = "8.8.8.8";   // Google DNS
        private const string AnchorIpAlt       = "1.1.1.1";   // Cloudflare DNS

        private ConnectivityState _currentState = ConnectivityState.Unknown;
        private DateTime _lastCheckUtc = DateTime.MinValue;
        private CancellationTokenSource? _monitorCts;

        public ConnectivityState CurrentState => _currentState;
        public DateTime LastCheckUtc          => _lastCheckUtc;

        public event EventHandler<ConnectivityState>? StateChanged;

        public void Start()
        {
            if (_monitorCts != null) return;
            _monitorCts = new CancellationTokenSource();
            // Background loop — never awaited from UI.
            _ = Task.Run(() => MonitorLoopAsync(_monitorCts.Token));
        }

        public void Stop()
        {
            try { _monitorCts?.Cancel(); } catch { }
            try { _monitorCts?.Dispose(); } catch { }
            _monitorCts = null;
        }

        public async Task<ConnectivityState> CheckNowAsync(CancellationToken ct)
        {
            var newState = await ProbeConnectivityAsync(ct).ConfigureAwait(false);
            ApplyState(newState);
            return newState;
        }

        private async Task MonitorLoopAsync(CancellationToken ct)
        {
            // Initial probe immediately so the UI doesn't sit on Unknown
            // for 30 s after launch.
            try
            {
                var initial = await ProbeConnectivityAsync(ct).ConfigureAwait(false);
                ApplyState(initial);
            }
            catch (Exception ex) { Logger.Debug(ex, "[CONN] Initial probe failed"); }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(CheckIntervalSeconds), ct)
                        .ConfigureAwait(false);
                    var state = await ProbeConnectivityAsync(ct).ConfigureAwait(false);
                    ApplyState(state);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    Logger.Debug(ex, "[CONN] Monitor loop error");
                }
            }
        }

        private async Task<ConnectivityState> ProbeConnectivityAsync(CancellationToken ct)
        {
            using var ping = new Ping();
            foreach (var anchor in new[] { AnchorIp, AnchorIpAlt })
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    var reply = await ping.SendPingAsync(anchor, PingTimeoutMs)
                        .ConfigureAwait(false);
                    if (reply.Status == IPStatus.Success)
                    {
                        return ConnectivityState.InternetReachable;
                    }
                }
                catch (Exception ex)
                {
                    Logger.Debug(ex, $"[CONN] Anchor {anchor} failed");
                }
            }

            // Internet anchors failed. Differentiate "no network at all"
            // from "LAN reachable, internet down" via gateway presence.
            bool hasLocalGateway;
            try
            {
                hasLocalGateway = NetworkInterface.GetAllNetworkInterfaces()
                    .Where(n => n.OperationalStatus == OperationalStatus.Up)
                    .Any(n => n.GetIPProperties().GatewayAddresses
                        .Any(g => g.Address != null && !g.Address.ToString().StartsWith("0.")));
            }
            catch
            {
                hasLocalGateway = false;
            }

            return hasLocalGateway
                ? ConnectivityState.LocalOnly
                : ConnectivityState.Unknown;
        }

        private void ApplyState(ConnectivityState newState)
        {
            _lastCheckUtc = DateTime.UtcNow;
            if (newState != _currentState)
            {
                var old = _currentState;
                _currentState = newState;
                Logger.Info($"[CONN] State changed: {old} → {newState}");
                try { StateChanged?.Invoke(this, newState); }
                catch (Exception ex) { Logger.Debug(ex, "[CONN] StateChanged listener failed"); }
            }
        }
    }
}
