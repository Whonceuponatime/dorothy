using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;
using NLog;

namespace Dorothy.Services.Probes
{
    public class HostEnrichmentService
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();

        private const int DnsTimeoutMs = 2000;
        private const int NetBiosTimeoutMs = 2000;
        private const int NetBiosPort = 137;
        private const int SnmpTimeoutMs = 3000;
        private const int SnmpPort = 161;

        public record EnrichmentResult(
            string? ReverseDnsHostname,
            string? NetBiosName,
            string? NetBiosWorkgroup,
            string? MdnsHostname,
            string? SnmpSysName,
            string? SnmpSysDescr,
            string? SnmpSysContact,
            string? SnmpSysLocation,
            // sysObjectID (1.3.6.1.2.1.1.2.0) — drives Survey vendor-hint
            // lookup via IndustrialVendorDatabase.LookupBySysObjectID.
            string? SnmpSysObjectId);

        public async Task<EnrichmentResult> EnrichAsync(
            string ipAddress,
            string snmpCommunity,
            CancellationToken ct)
        {
            var dnsTask = ReverseDnsAsync(ipAddress, ct);
            var netbiosTask = NetBiosQueryAsync(ipAddress, ct);
            var snmpTask = Task.Run(() => SnmpQuery(ipAddress, snmpCommunity, ct), ct);

            try
            {
                await Task.WhenAll(dnsTask, netbiosTask, snmpTask).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { }
            catch (Exception ex) { Logger.Debug(ex, "EnrichAsync: one or more sub-tasks faulted (ignored)"); }

            var dns = SafeResult(dnsTask, (string?)null);
            var nb = SafeResult(netbiosTask, ((string?)null, (string?)null));
            var snmp = SafeResult(snmpTask, new SnmpValues());

            return new EnrichmentResult(
                ReverseDnsHostname: dns,
                NetBiosName: nb.Item1,
                NetBiosWorkgroup: nb.Item2,
                MdnsHostname: null,
                SnmpSysName: snmp.SysName,
                SnmpSysDescr: snmp.SysDescr,
                SnmpSysContact: snmp.SysContact,
                SnmpSysLocation: snmp.SysLocation,
                SnmpSysObjectId: snmp.SysObjectId);
        }

        private static T SafeResult<T>(Task<T> task, T fallback)
        {
            try { return task.IsCompletedSuccessfully ? task.Result : fallback; }
            catch { return fallback; }
        }

        private static async Task<string?> ReverseDnsAsync(string ip, CancellationToken ct)
        {
            try
            {
                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeoutCts.CancelAfter(DnsTimeoutMs);
                var entry = await Dns.GetHostEntryAsync(ip, timeoutCts.Token).ConfigureAwait(false);
                var host = entry?.HostName;
                if (string.IsNullOrWhiteSpace(host)) return null;
                if (string.Equals(host, ip, StringComparison.Ordinal)) return null;
                return host;
            }
            catch { return null; }
        }

        private static async Task<(string?, string?)> NetBiosQueryAsync(string ip, CancellationToken ct)
        {
            try
            {
                if (!IPAddress.TryParse(ip, out var targetIp)) return (null, null);

                var query = BuildNbstatQuery();

                using var udp = new UdpClient();
                udp.Client.ReceiveTimeout = NetBiosTimeoutMs;
                udp.Client.SendTimeout = NetBiosTimeoutMs;

                var endpoint = new IPEndPoint(targetIp, NetBiosPort);
                await udp.SendAsync(query, query.Length, endpoint).ConfigureAwait(false);

                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeoutCts.CancelAfter(NetBiosTimeoutMs);

                UdpReceiveResult received;
                try
                {
                    received = await udp.ReceiveAsync(timeoutCts.Token).ConfigureAwait(false);
                }
                catch { return (null, null); }

                return ParseNbstatResponse(received.Buffer);
            }
            catch { return (null, null); }
        }

        private static byte[] BuildNbstatQuery()
        {
            var pkt = new byte[50];
            pkt[0] = 0x81; pkt[1] = 0x50;
            pkt[2] = 0x00; pkt[3] = 0x00;
            pkt[4] = 0x00; pkt[5] = 0x01;
            pkt[6] = 0x00; pkt[7] = 0x00;
            pkt[8] = 0x00; pkt[9] = 0x00;
            pkt[10] = 0x00; pkt[11] = 0x00;

            pkt[12] = 0x20;
            for (int i = 0; i < 32; i++) pkt[13 + i] = (byte)'C';
            pkt[45] = 0x00;

            pkt[46] = 0x00; pkt[47] = 0x21;
            pkt[48] = 0x00; pkt[49] = 0x01;
            return pkt;
        }

        private static (string?, string?) ParseNbstatResponse(byte[] buf)
        {
            if (buf == null || buf.Length < 57) return (null, null);

            int offset = 12;
            while (offset < buf.Length && buf[offset] != 0)
            {
                int len = buf[offset];
                offset += 1 + len;
            }
            offset++;
            offset += 4;

            offset += 2;
            offset += 2;
            offset += 4;
            offset += 2;

            if (offset >= buf.Length) return (null, null);
            int numNames = buf[offset];
            offset++;

            string? machineName = null;
            string? workgroup = null;

            for (int i = 0; i < numNames && offset + 18 <= buf.Length; i++)
            {
                var nameBytes = new byte[15];
                Array.Copy(buf, offset, nameBytes, 0, 15);
                var name = Encoding.ASCII.GetString(nameBytes).TrimEnd(' ', '\0');
                byte suffix = buf[offset + 15];
                ushort flags = (ushort)((buf[offset + 16] << 8) | buf[offset + 17]);
                bool isGroup = (flags & 0x8000) != 0;
                offset += 18;

                if (string.IsNullOrWhiteSpace(name)) continue;

                if (!isGroup && machineName == null && suffix == 0x00)
                    machineName = name;
                else if (isGroup && workgroup == null && (suffix == 0x00 || suffix == 0x1E))
                    workgroup = name;
            }

            return (machineName, workgroup);
        }

        private record SnmpValues
        {
            public string? SysDescr { get; init; }
            public string? SysContact { get; init; }
            public string? SysName { get; init; }
            public string? SysLocation { get; init; }
            public string? SysObjectId { get; init; }
        }

        private static SnmpValues SnmpQuery(string ip, string community, CancellationToken ct)
        {
            string? sysDescr = null, sysContact = null, sysName = null, sysLocation = null, sysObjectId = null;
            try
            {
                if (!IPAddress.TryParse(ip, out var ipAddr)) return new SnmpValues();
                var endpoint = new IPEndPoint(ipAddr, SnmpPort);
                var communityObject = new OctetString(string.IsNullOrWhiteSpace(community) ? "public" : community);

                var oids = new (string Oid, int Slot)[]
                {
                    ("1.3.6.1.2.1.1.1.0", 0),  // sysDescr
                    ("1.3.6.1.2.1.1.4.0", 1),  // sysContact
                    ("1.3.6.1.2.1.1.5.0", 2),  // sysName
                    ("1.3.6.1.2.1.1.6.0", 3),  // sysLocation
                    ("1.3.6.1.2.1.1.2.0", 4)   // sysObjectID — vendor enterprise OID
                };

                foreach (var (oid, slot) in oids)
                {
                    if (ct.IsCancellationRequested) break;
                    try
                    {
                        var variables = new List<Variable> { new Variable(new ObjectIdentifier(oid)) };
                        var reply = Messenger.Get(
                            VersionCode.V2,
                            endpoint,
                            communityObject,
                            variables,
                            SnmpTimeoutMs);

                        if (reply != null && reply.Count > 0)
                        {
                            var value = reply[0].Data?.ToString();
                            switch (slot)
                            {
                                case 0: sysDescr = value; break;
                                case 1: sysContact = value; break;
                                case 2: sysName = value; break;
                                case 3: sysLocation = value; break;
                                case 4: sysObjectId = value; break;
                            }
                        }
                    }
                    catch (Lextm.SharpSnmpLib.Messaging.TimeoutException) { }
                    catch (SocketException) { }
                    catch (Exception ex) { Logger.Debug(ex, $"SNMP GET failed for {ip} {oid}"); }
                }
            }
            catch (Exception ex) { Logger.Debug(ex, $"SNMP query failed for {ip}"); }

            return new SnmpValues
            {
                SysDescr = sysDescr,
                SysContact = sysContact,
                SysName = sysName,
                SysLocation = sysLocation,
                SysObjectId = sysObjectId
            };
        }
    }
}
