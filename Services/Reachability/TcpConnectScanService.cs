using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Dorothy.Services.Reachability
{

    public sealed class TcpConnectScanService
    {
        private readonly IcmpProbeService _icmpProbe = new();

        public async Task<TcpPortResult> ProbePortAsync(
            IPAddress  target,
            int        port,
            int        timeoutMs,
            CancellationToken ct,
            IPAddress? sourceIp = null)
        {
            var sw = Stopwatch.StartNew();

            using var probeCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            probeCts.CancelAfter(timeoutMs);

            try
            {
                using var client = new TcpClient();

                if (sourceIp != null &&
                    !sourceIp.Equals(IPAddress.None) &&
                    !sourceIp.Equals(IPAddress.Any))
                    client.Client.Bind(new IPEndPoint(sourceIp, 0));

                await client.ConnectAsync(target, port, probeCts.Token).ConfigureAwait(false);
                return new TcpPortResult
                {
                    Port  = port,
                    State = PortState.Open,
                    RttMs = sw.ElapsedMilliseconds
                };
            }
            catch (SocketException ex)
            {
                var state = ex.SocketErrorCode switch
                {
                    SocketError.ConnectionRefused  => PortState.Closed,
                    SocketError.NetworkUnreachable => PortState.NetworkUnreachable,
                    SocketError.HostUnreachable    => PortState.HostUnreachable,
                    _                              => PortState.Error
                };
                return new TcpPortResult
                {
                    Port  = port,
                    State = state,
                    RttMs = sw.ElapsedMilliseconds,
                    Error = state == PortState.Error ? ex.Message : null
                };
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {

                return new TcpPortResult
                {
                    Port  = port,
                    State = PortState.TimedOut,
                    RttMs = sw.ElapsedMilliseconds
                };
            }

            catch (Exception ex)
            {
                return new TcpPortResult
                {
                    Port  = port,
                    State = PortState.Error,
                    RttMs = sw.ElapsedMilliseconds,
                    Error = ex.Message
                };
            }
        }

        public async Task<List<HostScanResult>> ScanAsync(
            IReadOnlyList<IPAddress>   hosts,
            IReadOnlyList<int>         ports,
            ScanOptions                options,
            Action<HostScanResult>     onHostUpdated,
            IProgress<ScanProgress>?   progress,
            CancellationToken          ct)
        {

            var results = new List<HostScanResult>(hosts.Count);
            foreach (var h in hosts)
                results.Add(new HostScanResult { Target = h, Status = HostScanStatus.Pending });

            foreach (var r in results) onHostUpdated(r);

            int completedHosts = 0;
            var sem = new SemaphoreSlim(options.MaxConcurrency);

            var tasks = new List<Task>(hosts.Count);
            foreach (var result in results)
            {
                var r = result;
                tasks.Add(Task.Run(async () =>
                {
                    await sem.WaitAsync(ct).ConfigureAwait(false);
                    try
                    {
                        r.Status = HostScanStatus.Scanning;
                        onHostUpdated(r);

                        if (options.UseIcmpDiscovery && !ct.IsCancellationRequested)
                        {
                            r.IcmpResult = await _icmpProbe.ProbeAsync(
                                r.Target, options.IcmpPingCount, options.IcmpTimeoutMs, ct)
                                .ConfigureAwait(false);
                            onHostUpdated(r);
                        }

                        foreach (var port in ports)
                        {
                            if (ct.IsCancellationRequested) break;
                            var portResult = await ProbePortAsync(
                                r.Target, port, options.PerProbeTimeoutMs, ct, options.SourceIp)
                                .ConfigureAwait(false);
                            r.TcpResults.Add(portResult);
                            onHostUpdated(r);
                        }

                        r.Status = r.HasAnyDefinitiveResponse
                            ? HostScanStatus.Done
                            : HostScanStatus.Unreachable;
                        onHostUpdated(r);
                    }
                    catch (OperationCanceledException)
                    {
                        r.Status = HostScanStatus.Error;
                        r.ErrorMessage = "Cancelled";
                        onHostUpdated(r);
                    }
                    catch (Exception ex)
                    {
                        r.Status = HostScanStatus.Error;
                        r.ErrorMessage = ex.Message;
                        onHostUpdated(r);
                    }
                    finally
                    {
                        int done = Interlocked.Increment(ref completedHosts);
                        progress?.Report(new ScanProgress(done, hosts.Count,
                            $"Completed {r.Target}"));
                        sem.Release();
                    }
                }, ct));
            }

            await Task.WhenAll(tasks).ConfigureAwait(false);
            return results;
        }
    }
}
