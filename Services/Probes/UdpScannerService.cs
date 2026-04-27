using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Dorothy.Models;
using NLog;

namespace Dorothy.Services.Probes
{
    /// <summary>
    /// UDP top-20 port scan with port-specific probe payloads. Listens 2s
    /// for any response (or ICMP port unreachable mapped to ConnectionReset).
    /// Used by the Full and Deep probe tiers.
    /// </summary>
    public class UdpScannerService
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();

        private const int TimeoutMs = 2000;
        private const int MaxConcurrent = 5;

        private static readonly int[] Top20UdpPorts =
        {
            53, 67, 68, 69, 123, 137, 138, 161, 162, 500,
            514, 520, 631, 1900, 5353, 5060, 4500, 1701,
            1812, 1813
        };

        public async Task<List<UdpScanResult>> ScanAsync(string ipAddress, CancellationToken ct)
        {
            var results = new List<UdpScanResult>(Top20UdpPorts.Length);
            if (!IPAddress.TryParse(ipAddress, out _)) return results;

            using var gate = new SemaphoreSlim(MaxConcurrent, MaxConcurrent);
            var tasks = Top20UdpPorts.Select(p => ScanOneAsync(ipAddress, p, gate, ct)).ToList();

            UdpScanResult[] collected;
            try
            {
                collected = await Task.WhenAll(tasks).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { return results; }

            results.AddRange(collected);
            return results;
        }

        private static async Task<UdpScanResult> ScanOneAsync(
            string ipAddress, int port, SemaphoreSlim gate, CancellationToken ct)
        {
            await gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                using var udp = new UdpClient();
                udp.Client.ReceiveTimeout = TimeoutMs;
                udp.Client.SendTimeout = TimeoutMs;

                var endpoint = new IPEndPoint(IPAddress.Parse(ipAddress), port);
                var probe = BuildProbeFor(port, ipAddress);

                try
                {
                    await udp.SendAsync(probe, probe.Length, endpoint).ConfigureAwait(false);
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset)
                {
                    return new UdpScanResult(port, UdpStatus.Closed, null, IdentifyService(port));
                }
                catch
                {
                    return new UdpScanResult(port, UdpStatus.OpenOrFiltered, null, IdentifyService(port));
                }

                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeoutCts.CancelAfter(TimeoutMs);

                try
                {
                    var received = await udp.ReceiveAsync(timeoutCts.Token).ConfigureAwait(false);
                    var raw = received.Buffer != null && received.Buffer.Length > 0
                        ? PreviewBytes(received.Buffer, 64)
                        : null;
                    return new UdpScanResult(port, UdpStatus.Open, raw, IdentifyService(port));
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset)
                {
                    return new UdpScanResult(port, UdpStatus.Closed, null, IdentifyService(port));
                }
                catch
                {
                    // No response within timeout, no ICMP unreachable.
                    return new UdpScanResult(port, UdpStatus.OpenOrFiltered, null, IdentifyService(port));
                }
            }
            catch (Exception ex)
            {
                Logger.Debug(ex, $"UDP scan port {port} on {ipAddress} failed");
                return new UdpScanResult(port, UdpStatus.OpenOrFiltered, null, IdentifyService(port));
            }
            finally
            {
                gate.Release();
            }
        }

        private static byte[] BuildProbeFor(int port, string targetIp)
        {
            switch (port)
            {
                case 53:   return BuildDnsQuery();
                case 123:  return BuildNtpRequest();
                case 137:  return BuildNbstatQuery();
                case 161:  return BuildSnmpGetSysDescr();
                case 1900: return BuildSsdpMSearch();
                case 5353: return BuildMdnsQuery();
                case 500:  return BuildIkeProbe();
                default:   return new byte[8]; // generic 8 zero bytes
            }
        }

        // CHAOS-class TXT query for "version.bind" — the standard fingerprint
        // probe used by dig/fpdns. Many BIND/PowerDNS/Unbound servers answer
        // it with their version string; servers that don't still reply NOERROR
        // or REFUSED, which is enough to mark the port Open.
        private static byte[] BuildDnsQuery()
        {
            return new byte[]
            {
                0x12, 0x34,             // transaction ID
                0x01, 0x00,             // flags: standard query
                0x00, 0x01,             // QDCOUNT = 1
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x07, (byte)'v',(byte)'e',(byte)'r',(byte)'s',(byte)'i',(byte)'o',(byte)'n',
                0x04, (byte)'b',(byte)'i',(byte)'n',(byte)'d',
                0x00,                   // end of name
                0x00, 0x10,             // QTYPE = TXT
                0x00, 0x03              // QCLASS = CHAOS
            };
        }

        // SNTP/NTP version 3 client request
        private static byte[] BuildNtpRequest()
        {
            var pkt = new byte[48];
            pkt[0] = 0x1B; // LI=0, VN=3, Mode=3 (client)
            return pkt;
        }

        // NetBIOS Node Status Request
        private static byte[] BuildNbstatQuery()
        {
            var pkt = new byte[50];
            pkt[0] = 0x81; pkt[1] = 0x50;
            pkt[5] = 0x01;
            pkt[12] = 0x20;
            for (int i = 0; i < 32; i++) pkt[13 + i] = (byte)'C';
            pkt[46] = 0x00; pkt[47] = 0x21;
            pkt[48] = 0x00; pkt[49] = 0x01;
            return pkt;
        }

        // SNMPv2c GET sysDescr (1.3.6.1.2.1.1.1.0) with community "public"
        private static byte[] BuildSnmpGetSysDescr()
        {
            return new byte[]
            {
                0x30, 0x29,
                0x02, 0x01, 0x01,                   // version: 2c (1)
                0x04, 0x06, (byte)'p',(byte)'u',(byte)'b',(byte)'l',(byte)'i',(byte)'c',
                0xA0, 0x1C,                          // GET request PDU
                0x02, 0x04, 0x12, 0x34, 0x56, 0x78,  // request ID
                0x02, 0x01, 0x00,                    // error status
                0x02, 0x01, 0x00,                    // error index
                0x30, 0x0E,                          // varbind list
                0x30, 0x0C,                          // varbind
                0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,
                0x05, 0x00                           // value: NULL
            };
        }

        // SSDP M-SEARCH (UPnP discovery)
        private static byte[] BuildSsdpMSearch()
        {
            var msg = "M-SEARCH * HTTP/1.1\r\n" +
                      "HOST: 239.255.255.250:1900\r\n" +
                      "MAN: \"ssdp:discover\"\r\n" +
                      "MX: 2\r\n" +
                      "ST: ssdp:all\r\n\r\n";
            return Encoding.ASCII.GetBytes(msg);
        }

        // mDNS PTR query for _services._dns-sd._udp.local
        private static byte[] BuildMdnsQuery()
        {
            return new byte[]
            {
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x09, (byte)'_',(byte)'s',(byte)'e',(byte)'r',(byte)'v',(byte)'i',(byte)'c',(byte)'e',(byte)'s',
                0x07, (byte)'_',(byte)'d',(byte)'n',(byte)'s',(byte)'-',(byte)'s',(byte)'d',
                0x04, (byte)'_',(byte)'u',(byte)'d',(byte)'p',
                0x05, (byte)'l',(byte)'o',(byte)'c',(byte)'a',(byte)'l',
                0x00,
                0x00, 0x0C,
                0x00, 0x01
            };
        }

        // ISAKMP probe — minimal IKE Header with no payloads
        private static byte[] BuildIkeProbe()
        {
            return new byte[]
            {
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,
                0x10, 0x02,
                0,
                0x00,0x00,0x00,0x00,
                0,0,0, 0x1C
            };
        }

        private static string PreviewBytes(byte[] buf, int max)
        {
            int n = Math.Min(buf.Length, max);
            var sb = new StringBuilder(n * 2);
            for (int i = 0; i < n; i++) sb.Append(buf[i].ToString("x2"));
            return sb.ToString();
        }

        private static string? IdentifyService(int port) => port switch
        {
            53   => "DNS",
            67   => "DHCP-server",
            68   => "DHCP-client",
            69   => "TFTP",
            123  => "NTP",
            137  => "NetBIOS-NS",
            138  => "NetBIOS-DGM",
            161  => "SNMP",
            162  => "SNMP-trap",
            500  => "ISAKMP/IKE",
            514  => "syslog",
            520  => "RIP",
            631  => "IPP",
            1701 => "L2TP",
            1812 => "RADIUS-auth",
            1813 => "RADIUS-acct",
            1900 => "SSDP",
            4500 => "IPsec-NAT-T",
            5060 => "SIP",
            5353 => "mDNS",
            _    => null
        };
    }
}
