using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;

namespace Dorothy.Services.Reachability
{

    public sealed class TracerouteService
    {
        private const int DnsTimeoutMs = 1500;

        public async Task<List<PathHopResult>> TraceAsync(
            IPAddress     target,
            int           maxHops          = 30,
            int           timeoutMs        = 4000,
            bool          resolveHostnames = false,
            CancellationToken ct           = default)
        {
            var hops = new List<PathHopResult>();

            for (int ttl = 1; ttl <= maxHops; ttl++)
            {
                if (ct.IsCancellationRequested) break;

                var options = new PingOptions(ttl, false);
                byte[] buffer = new byte[32];

                IPAddress? hopIp = null;
                long rttMs = 0;

                try
                {
                    using var ping = new Ping();
                    var reply = await ping.SendPingAsync(target, timeoutMs, buffer, options)
                        .ConfigureAwait(false);

                    if (reply != null &&
                        (reply.Status == IPStatus.TtlExpired || reply.Status == IPStatus.Success))
                    {
                        hopIp  = reply.Address;
                        rttMs  = reply.RoundtripTime;
                    }
                }
                catch (PingException) {  }

                var hop = new PathHopResult
                {
                    HopNumber = ttl,
                    HopIp     = hopIp,
                    RttMs     = rttMs
                };
                hops.Add(hop);

                if (hopIp != null && hopIp.Equals(target)) break;

                if (hopIp == null && hops.Count >= 3 &&
                    hops[hops.Count - 1].HopIp == null &&
                    hops[hops.Count - 2].HopIp == null &&
                    hops[hops.Count - 3].HopIp == null)
                    break;
            }

            if (resolveHostnames)
                await ResolveHostnamesAsync(hops, ct).ConfigureAwait(false);

            return hops;
        }

        private static async Task ResolveHostnamesAsync(
            List<PathHopResult> hops, CancellationToken ct)
        {
            var tasks = new List<Task>(hops.Count);
            foreach (var hop in hops)
            {
                if (hop.HopIp == null) continue;
                var h = hop;
                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        using var dnsCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                        dnsCts.CancelAfter(DnsTimeoutMs);
                        var entry = await Dns.GetHostEntryAsync(h.HopIp!.ToString())
                            .WaitAsync(dnsCts.Token).ConfigureAwait(false);
                        h.Hostname = entry.HostName;
                    }
                    catch {  }
                }, CancellationToken.None));
            }
            await Task.WhenAll(tasks).ConfigureAwait(false);
        }
    }
}
