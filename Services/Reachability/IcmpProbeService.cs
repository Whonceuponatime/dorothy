using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;

namespace Dorothy.Services.Reachability
{

    public sealed class IcmpProbeService
    {

        public async Task<IcmpProbeResult> ProbeAsync(
            IPAddress target,
            int       count,
            int       timeoutMs,
            CancellationToken ct = default)
        {
            int received = 0;
            long totalRtt = 0;

            for (int i = 0; i < count; i++)
            {
                if (ct.IsCancellationRequested) break;

                try
                {
                    using var ping = new Ping();
                    var reply = await ping.SendPingAsync(target, timeoutMs);
                    if (reply?.Status == IPStatus.Success)
                    {
                        received++;
                        totalRtt += reply.RoundtripTime;
                    }
                }
                catch
                {

                }

                if (i < count - 1 && !ct.IsCancellationRequested)
                    await Task.Delay(150, ct).ConfigureAwait(false);
            }

            return new IcmpProbeResult
            {
                Target      = target,
                Reachable   = received > 0,
                ReplyStatus = received > 0 ? IcmpReplyStatus.Reply : IcmpReplyStatus.NoReply,
                Sent        = count,
                Received    = received,
                AvgRttMs    = received > 0 ? totalRtt / received : 0
            };
        }
    }
}
