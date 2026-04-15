using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Dorothy.Network
{
    public static class HostnameResolver
    {

        public static async Task<string?> ResolveHostnameAsync(IPAddress ip, int timeoutMs = 1000)
        {
            try
            {
                using var cts = new CancellationTokenSource(timeoutMs);

                var dnsTask = Dns.GetHostEntryAsync(ip);

                var completed = await Task.WhenAny(dnsTask, Task.Delay(timeoutMs, cts.Token));
                if (completed != dnsTask)
                    return null;

                var entry = await dnsTask;
                if (entry == null)
                    return null;

                var hostName = entry.HostName;
                if (string.IsNullOrWhiteSpace(hostName))
                    return null;

                var shortName = hostName.Split('.')[0];
                return shortName;
            }
            catch (SocketException)
            {

                return null;
            }
            catch
            {
                return null;
            }
        }
    }
}

