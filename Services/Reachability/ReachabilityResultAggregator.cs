using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Dorothy.Services.Reachability
{

    public sealed class ReachabilityResultAggregator
    {

        private static readonly IReadOnlyDictionary<int, string> ServiceNames =
            new Dictionary<int, string>
            {
                {21,"FTP"},{22,"SSH"},{23,"Telnet"},{25,"SMTP"},
                {53,"DNS"},{80,"HTTP"},{110,"POP3"},{135,"RPC"},
                {139,"NetBIOS"},{143,"IMAP"},{443,"HTTPS"},{445,"SMB"},
                {502,"Modbus"},{993,"IMAPS"},{995,"POP3S"},
                {1433,"MSSQL"},{1521,"Oracle"},{3306,"MySQL"},
                {3389,"RDP"},{4899,"Radmin"},{5432,"PostgreSQL"},
                {5900,"VNC"},{5901,"VNC-1"},{8080,"HTTP-Alt"},
                {8443,"HTTPS-Alt"},{8888,"HTTP-Alt2"},{3000,"HTTP-Dev"}
            };

        private static string PortLabel(int port) =>
            ServiceNames.TryGetValue(port, out var name) ? $"{port} ({name})" : port.ToString();

        private static string PortList(IEnumerable<TcpPortResult> ports) =>
            string.Join(", ", ports.Select(p => PortLabel(p.Port)));

        private static string RouteLabel(RouteType r) => r switch
        {
            RouteType.OnLink     => "On-link (same subnet)",
            RouteType.ViaGateway => "Via gateway (routed)",
            RouteType.NoRoute    => "No route / NetworkUnreachable",
            _                    => "Unknown"
        };

        private static string IcmpLabel(IcmpProbeResult? r)
        {
            if (r == null) return "Not tested";
            return r.ReplyStatus switch
            {
                IcmpReplyStatus.Reply   => $"Reply  (avg {r.AvgRttMs} ms, {r.Received}/{r.Sent} probes)",
                IcmpReplyStatus.NoReply => $"No reply  ({r.Sent} probes — may be blocked or filtered)",
                IcmpReplyStatus.Error   => "Error during probe",
                _                       => "Not tested"
            };
        }

        private static string IcmpShort(IcmpProbeResult? r) =>
            r?.ReplyStatus switch
            {
                IcmpReplyStatus.Reply   => "Reply",
                IcmpReplyStatus.NoReply => "No reply",
                IcmpReplyStatus.Error   => "Error",
                _                       => "—"
            };

        private static void AppendContextHeader(StringBuilder sb, ReportContext? ctx)
        {
            if (ctx == null) return;
            if (!string.IsNullOrEmpty(ctx.NicDisplayName))
                sb.AppendLine($"Selected NIC:         {ctx.NicDisplayName}");
            if (ctx.SourceIp != null && !ctx.SourceIp.Equals(System.Net.IPAddress.None))
                sb.AppendLine($"Source IP:            {ctx.SourceIp}");
            if (ctx.Route != RouteType.Unknown)
                sb.AppendLine($"Route:                {RouteLabel(ctx.Route)}");
            if (!string.IsNullOrEmpty(ctx.BoundaryGateway))
                sb.AppendLine($"Boundary/Gateway:     {ctx.BoundaryGateway}");
        }

        public string GenerateSimpleReachabilityText(
            HostScanResult      result,
            List<PathHopResult> pathHops,
            string?             label   = null,
            ReportContext?      context = null)
        {
            var sb = new StringBuilder();

            string target = label != null
                ? $"{result.Target}  ({label})"
                : result.Target.ToString();
            sb.AppendLine($"Target:               {target}");
            sb.AppendLine($"Resolution:           {context?.TargetResolution ?? "IP"}");
            sb.AppendLine($"Date/Time:            {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            AppendContextHeader(sb, context);
            sb.AppendLine();

            sb.AppendLine($"ICMP:                 {IcmpLabel(result.IcmpResult)}");

            var open     = result.OpenPorts.ToList();
            var closed   = result.ClosedPorts.ToList();
            var timedOut = result.TimedOutPorts.ToList();
            var errors   = result.ErrorPorts.ToList();

            sb.AppendLine($"Open ports:           {(open.Count    > 0 ? PortList(open)    : "None")}");
            sb.AppendLine($"Closed ports:         {(closed.Count  > 0 ? PortList(closed)  : "None")}");
            sb.AppendLine($"Timed out / filtered: {(timedOut.Count > 0 ? PortList(timedOut) : "None")}");
            if (errors.Count > 0)
                sb.AppendLine($"Error:                {PortList(errors)}");

            sb.AppendLine($"Path observation:     {BuildPathObservation(result.Target, pathHops)}");

            sb.AppendLine("Interpretation:");
            sb.AppendLine(BuildSimpleInterpretation(result, pathHops));

            return sb.ToString();
        }

        public string GenerateScanSummary(
            IReadOnlyList<HostScanResult> results,
            string                        targetDescription,
            IReadOnlyList<int>            portsScanned,
            ScanOptions                   options,
            ReportContext?                context = null)
        {
            var sb = new StringBuilder();

            string portStr = string.Join(", ", portsScanned.Select(PortLabel));
            sb.AppendLine($"Target:           {targetDescription}");
            sb.AppendLine($"Resolution:       {context?.TargetResolution ?? "IP"}");
            sb.AppendLine($"Date/Time:        {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            AppendContextHeader(sb, context);
            sb.AppendLine($"ICMP discovery:   {(options.UseIcmpDiscovery ? "enabled" : "disabled")}");
            sb.AppendLine($"Ports tested:     {portStr}");
            sb.AppendLine($"Concurrency:      {options.MaxConcurrency}  |  Timeout: {options.PerProbeTimeoutMs} ms");
            sb.AppendLine();

            int total       = results.Count;
            int withOpen    = results.Count(r => r.OpenPorts.Any());
            int responded   = results.Count(r => r.HasAnyDefinitiveResponse);
            int unreachable = results.Count(r => r.Status == HostScanStatus.Unreachable);
            int unresolved  = results.Count(r => r.Status == HostScanStatus.UnresolvedName);
            int errCount    = results.Count(r => r.Status == HostScanStatus.Error);
            int totalOpen   = results.Sum(r => r.OpenPorts.Count());

            sb.AppendLine("Results:");
            sb.AppendLine($"  Hosts with open ports:           {withOpen}");
            sb.AppendLine($"  Total open ports found:          {totalOpen}");
            sb.AppendLine($"  Hosts with definitive response:  {responded}");
            sb.AppendLine($"  Total hosts scanned:             {total}");
            sb.AppendLine($"  Unreachable / fully filtered:    {unreachable}");
            if (unresolved > 0)
                sb.AppendLine($"  Unresolved names (not scanned):  {unresolved}");
            if (errCount > 0)
                sb.AppendLine($"  Scan errors:                     {errCount}");
            sb.AppendLine();

            if (withOpen > 0)
            {
                sb.AppendLine("Open ports found:");
                foreach (var r in results.Where(r => r.OpenPorts.Any())
                                         .OrderBy(r => r.Target.ToString()))
                {
                    string icmp = IcmpShort(r.IcmpResult);
                    string op   = PortList(r.OpenPorts);
                    string cl   = r.ClosedPorts.Any() ? PortList(r.ClosedPorts) : "0";
                    string to   = r.TimedOutPorts.Any() ? PortList(r.TimedOutPorts) : "0";
                    int    err  = r.ErrorPorts.Count();
                    sb.AppendLine($"  {r.Target,-18}  ICMP: {icmp,-3}  " +
                                  $"Open: {op}  Closed: {cl}  Timed out: {to}  Error: {err}");
                }
                sb.AppendLine();
            }

            var unresolvedRows = results.Where(r => r.Status == HostScanStatus.UnresolvedName).ToList();
            if (unresolvedRows.Any())
            {
                sb.AppendLine("Unresolved names (DNS failed — not scanned):");
                foreach (var r in unresolvedRows)
                    sb.AppendLine($"  {r.Target}  [{r.ErrorMessage ?? "hostname not resolved"}]");
                sb.AppendLine();
            }

            sb.AppendLine("Interpretation:");
            if (withOpen == 0 && responded == 0 && unreachable > 0)
                sb.AppendLine("  No hosts responded to any probe. Network may be isolated or all ports are filtered.");
            else if (withOpen == 0 && responded > 0)
                sb.AppendLine($"  {responded} host(s) responded (connection refused/closed) but no open ports found on the tested port set.");
            else if (withOpen > 0)
            {
                sb.AppendLine($"  {withOpen} host(s) have accessible TCP services.");
                var top = results.SelectMany(r => r.OpenPorts)
                                 .GroupBy(p => p.Port)
                                 .OrderByDescending(g => g.Count())
                                 .FirstOrDefault();
                if (top != null)
                    sb.AppendLine($"  Most common open port: {PortLabel(top.Key)} ({top.Count()} host(s)).");
                if (unreachable > 0)
                    sb.AppendLine($"  {unreachable} host(s) appear unreachable or fully filtered.");
            }
            if (unresolved > 0)
                sb.AppendLine($"  {unresolved} hostname(s) could not be resolved. Verify DNS/network connectivity or use IP addresses directly.");

            return sb.ToString();
        }

        private static string BuildPathObservation(
            System.Net.IPAddress target, List<PathHopResult> path)
        {
            if (path.Count == 0) return "Not performed";
            bool reached = path[path.Count - 1].HopIp?.Equals(target) == true;
            if (reached) return $"{path.Count} hop(s) — destination reached";
            var last = path[path.Count - 1];
            return last.HopIp != null
                ? $"{path.Count} hop(s) — path stops at {last.HopIpDisplay} (hop {last.HopNumber})"
                : $"{path.Count - 1} responding hop(s) — path stops before destination";
        }

        private static string BuildSimpleInterpretation(
            HostScanResult result, List<PathHopResult> path)
        {
            var sb = new StringBuilder();
            bool icmpOk    = result.IcmpResult?.Reachable ?? false;
            bool hasOpen   = result.OpenPorts.Any();
            bool hasClosed = result.ClosedPorts.Any();

            bool icmpNoReply = result.IcmpResult?.ReplyStatus == IcmpReplyStatus.NoReply;

            if (icmpOk && hasOpen)
                sb.AppendLine("  Host is reachable via ICMP and has accessible TCP services.");
            else if (icmpOk)
                sb.AppendLine("  Host responds to ICMP but no open ports found on the tested set.");
            else if (icmpNoReply && hasOpen)
            {
                sb.AppendLine("  ICMP: No reply — probe was blocked or filtered.");
                sb.AppendLine("  TCP reachability: Confirmed — open port(s) responded.");
                sb.AppendLine("  Note: ICMP no reply does NOT mean the host is down. TCP evidence confirms reachability.");
            }
            else if (icmpNoReply && hasClosed)
            {
                sb.AppendLine("  ICMP: No reply — probe was blocked or filtered.");
                sb.AppendLine("  TCP reachability: Host alive — connection refused (port closed) indicates an active TCP stack.");
                sb.AppendLine("  Note: ICMP no reply does NOT mean the host is down.");
            }
            else if (icmpNoReply)
            {
                sb.AppendLine("  ICMP: No reply — may be blocked/filtered/ignored by host or intermediate device.");
                sb.AppendLine("  TCP: No open or closed ports found on tested set — unable to confirm reachability.");
                sb.AppendLine("  Consider testing additional ports or using path analysis to determine routing.");
            }
            else
                sb.AppendLine("  Host did not respond to any probe. It may be offline, fully filtered, or unreachable.");

            foreach (var op in result.OpenPorts)
                sb.AppendLine($"  {PortLabel(op.Port)} is open.");
            foreach (var cp in result.ClosedPorts)
                sb.AppendLine($"  {PortLabel(cp.Port)} is closed — service not running.");
            foreach (var tp in result.TimedOutPorts)
                sb.AppendLine($"  {PortLabel(tp.Port)} timed out — likely filtered by firewall.");
            foreach (var ep in result.ErrorPorts)
                sb.AppendLine($"  {PortLabel(ep.Port)} returned error: {ep.Error ?? "unknown"}.");

            bool pathReached = path.Count > 0 &&
                path[path.Count - 1].HopIp?.Equals(result.Target) == true;
            if (pathReached)
                sb.AppendLine($"  Path reaches destination in {path.Count} hop(s).");
            else if (path.Count > 0)
            {
                var last = path[path.Count - 1];
                sb.AppendLine(last.HopIp != null
                    ? $"  Path stops at hop {last.HopNumber} ({last.HopIpDisplay}) — destination not reached."
                    : $"  Path stops responding after hop {last.HopNumber - 1}. " +
                      "A firewall or routing gap may be present.");
            }

            return sb.ToString().TrimEnd();
        }
    }
}
