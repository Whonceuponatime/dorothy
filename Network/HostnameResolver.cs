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
        /// <summary>
        /// Tries to resolve hostname for an IP using DNS/LLMNR/hosts.
        /// Works offline (no Internet required) if there is local name resolution.
        /// </summary>
        public static async Task<string?> ResolveHostnameAsync(IPAddress ip, int timeoutMs = 1000)
        {
            try
            {
                using var cts = new CancellationTokenSource(timeoutMs);

                var dnsTask = Dns.GetHostEntryAsync(ip);

                // Basic timeout wrapper
                var completed = await Task.WhenAny(dnsTask, Task.Delay(timeoutMs, cts.Token));
                if (completed != dnsTask)
                    return null; // timed out

                var entry = await dnsTask;
                if (entry == null)
                    return null;

                // Prefer the short hostname (DESKTOP-ABC instead of DESKTOP-ABC.domain.local)
                var hostName = entry.HostName;
                if (string.IsNullOrWhiteSpace(hostName))
                    return null;

                var shortName = hostName.Split('.')[0];
                return shortName;
            }
            catch (SocketException)
            {
                // no PTR / no record
                return null;
            }
            catch
            {
                return null;
            }
        }
    }
}








