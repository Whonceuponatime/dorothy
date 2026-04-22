using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Dorothy.Models;

namespace Dorothy.Services.Probes
{
    public class OsFingerprintService
    {
        public record FingerprintResult(
            string OsFamily,
            string? OsVersion,
            double Confidence);

        public FingerprintResult Fingerprint(
            string? snmpSysDescr,
            IEnumerable<BannerInfo>? banners,
            IEnumerable<int>? openPorts)
        {
            var bannerList = banners?.ToList() ?? new List<BannerInfo>();
            var portSet = openPorts?.ToHashSet() ?? new HashSet<int>();

            if (!string.IsNullOrWhiteSpace(snmpSysDescr))
            {
                var descr = snmpSysDescr!;

                if (descr.IndexOf("Cisco IOS", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    descr.IndexOf("Cisco Internetwork", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    var m = Regex.Match(descr, @"Version\s+([\w\.\(\)]+)");
                    return new FingerprintResult("Cisco", m.Success ? m.Groups[1].Value : null, 0.95);
                }
                if (descr.IndexOf("MikroTik", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    descr.IndexOf("RouterOS", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    var m = Regex.Match(descr, @"RouterOS\s+([\d\.]+)");
                    return new FingerprintResult("MikroTik", m.Success ? m.Groups[1].Value : null, 0.95);
                }
                if (descr.IndexOf("VMware ESXi", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    var m = Regex.Match(descr, @"ESXi\s+([\d\.]+)");
                    return new FingerprintResult("VMware ESXi", m.Success ? m.Groups[1].Value : null, 0.95);
                }
                if (descr.IndexOf("Synology", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    var m = Regex.Match(descr, @"DSM\s+([\d\.]+)");
                    return new FingerprintResult("Synology DSM", m.Success ? m.Groups[1].Value : null, 0.9);
                }
                if (descr.IndexOf("QNAP", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    var m = Regex.Match(descr, @"(?:QTS|QuTS\s*hero)\s+([\d\.]+)");
                    return new FingerprintResult("QNAP", m.Success ? m.Groups[1].Value : null, 0.9);
                }
                if (descr.IndexOf("FreeBSD", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    var m = Regex.Match(descr, @"FreeBSD\s+([\d\.]+)");
                    return new FingerprintResult("FreeBSD", m.Success ? m.Groups[1].Value : null, 0.9);
                }
                if (descr.IndexOf("Linux", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    var m = Regex.Match(descr, @"Linux\s+\S+\s+([\d\.\-]+)");
                    return new FingerprintResult("Linux", m.Success ? m.Groups[1].Value : null, 0.9);
                }
                if (descr.IndexOf("Windows", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    var m = Regex.Match(descr, @"Windows[^\d]*([\d\.]+)");
                    return new FingerprintResult("Windows", m.Success ? m.Groups[1].Value : null, 0.9);
                }
                if (descr.IndexOf("Hardware: Intel(R)", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return new FingerprintResult("Windows", null, 0.7);
                }
                if (descr.IndexOf("JUNOS", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    var m = Regex.Match(descr, @"JUNOS\s+([\d\.\w]+)");
                    return new FingerprintResult("Juniper JunOS", m.Success ? m.Groups[1].Value : null, 0.95);
                }
                if (descr.IndexOf("HP", StringComparison.OrdinalIgnoreCase) >= 0 &&
                    descr.IndexOf("Printer", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return new FingerprintResult("HP Printer", null, 0.9);
                }
            }

            foreach (var b in bannerList)
            {
                if (string.IsNullOrEmpty(b.IdentifiedVersion)) continue;
                var v = b.IdentifiedVersion!;
                if (v.IndexOf("Microsoft-IIS", StringComparison.OrdinalIgnoreCase) >= 0)
                    return new FingerprintResult("Windows", v, 0.85);
                if (Regex.IsMatch(v, @"Apache.*\(Debian\)", RegexOptions.IgnoreCase))
                    return new FingerprintResult("Linux (Debian)", v, 0.9);
                if (Regex.IsMatch(v, @"Apache.*\(Ubuntu\)", RegexOptions.IgnoreCase))
                    return new FingerprintResult("Linux (Ubuntu)", v, 0.9);
                if (Regex.IsMatch(v, @"Apache.*\(CentOS\)|Apache.*\(Red Hat\)", RegexOptions.IgnoreCase))
                    return new FingerprintResult("Linux (RHEL/CentOS)", v, 0.9);
                if (v.IndexOf("nginx", StringComparison.OrdinalIgnoreCase) >= 0)
                    return new FingerprintResult("Linux", v, 0.6);
                if (v.IndexOf("OpenSSH", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    if (v.IndexOf("Ubuntu", StringComparison.OrdinalIgnoreCase) >= 0)
                        return new FingerprintResult("Linux (Ubuntu)", v, 0.9);
                    if (v.IndexOf("Debian", StringComparison.OrdinalIgnoreCase) >= 0)
                        return new FingerprintResult("Linux (Debian)", v, 0.9);
                    return new FingerprintResult("Linux", v, 0.7);
                }
            }

            if (portSet.Contains(9100))
                return new FingerprintResult("Printer", null, 0.7);
            if (portSet.Contains(502))
                return new FingerprintResult("Industrial (Modbus)", null, 0.8);
            if (portSet.Contains(1883))
                return new FingerprintResult("IoT (MQTT)", null, 0.7);

            bool winSigs = portSet.Contains(135) || portSet.Contains(139) || portSet.Contains(445);
            if (winSigs)
            {
                if (portSet.Contains(3389))
                    return new FingerprintResult("Windows", null, 0.8);
                return new FingerprintResult("Windows", null, 0.7);
            }

            if (portSet.Contains(22) && portSet.Contains(80))
                return new FingerprintResult("Linux", null, 0.6);

            if (portSet.Contains(3389))
                return new FingerprintResult("Windows", null, 0.6);

            if (portSet.Count > 0 && portSet.All(p => p == 161))
                return new FingerprintResult("SNMP-managed device", null, 0.5);

            if (portSet.Count == 1 && portSet.Contains(23))
                return new FingerprintResult("Embedded/legacy", null, 0.5);

            return new FingerprintResult("Unknown", null, 0.0);
        }
    }
}
