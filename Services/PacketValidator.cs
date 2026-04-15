using System;
using NLog;
using PacketDotNet;

namespace Dorothy.Services
{

    public sealed class ValidationResult
    {
        public bool   IsValid      { get; private init; }
        public string ErrorMessage { get; private init; } = string.Empty;

        public static ValidationResult Ok()             => new() { IsValid = true };
        public static ValidationResult Fail(string msg) => new() { IsValid = false, ErrorMessage = msg };
    }

    public static class PacketValidator
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();

        private const int EthLen     = 14;
        private const byte ProtoTcp  = 6;
        private const byte ProtoUdp  = 17;
        private const byte ProtoIcmp = 1;

        public static ValidationResult Validate(byte[] frame, string label = "")
        {
            if (frame.Length < EthLen + 20)
                return Fail(label, $"Frame too short: {frame.Length} bytes (min {EthLen + 20})");

            int ipStart = EthLen;
            int ipVer   = (frame[ipStart] >> 4) & 0xF;
            if (ipVer != 4)
                return Fail(label, $"Expected IPv4 but got version={ipVer}");

            int ipHeaderLen = (frame[ipStart] & 0x0F) * 4;
            if (ipHeaderLen < 20)
                return Fail(label, $"IP IHL={ipHeaderLen / 4} is too small (minimum 5 = 20 bytes)");

            int ipTotalLen = (frame[ipStart + 2] << 8) | frame[ipStart + 3];
            if (frame.Length < EthLen + ipTotalLen)
                return Fail(label,
                    $"IP TotalLength={ipTotalLen} but only {frame.Length - EthLen} bytes follow the Ethernet header");

            if (InternetSum16(frame, ipStart, ipHeaderLen) != 0)
            {
                ushort stored = (ushort)((frame[ipStart + 10] << 8) | frame[ipStart + 11]);
                return Fail(label, $"IP header checksum invalid (stored=0x{stored:X4})");
            }

            byte proto          = frame[ipStart + 9];
            int  transportStart = ipStart + ipHeaderLen;
            int  transportLen   = ipTotalLen - ipHeaderLen;

            return proto switch
            {
                ProtoTcp  => ValidateTcp (frame, ipStart, ipHeaderLen, transportStart, transportLen, label),
                ProtoUdp  => ValidateUdp (frame, ipStart,              transportStart, transportLen, label),
                ProtoIcmp => ValidateIcmp(frame,                       transportStart, transportLen, label),
                _         => ValidationResult.Ok()
            };
        }

        public static (int Valid, int Invalid) ValidatePool(byte[][] pool, string poolLabel)
        {
            int valid = 0, invalid = 0;
            for (int i = 0; i < pool.Length; i++)
            {
                if (pool[i] == null) continue;
                var r = Validate(pool[i], $"{poolLabel}[{i}]");
                if (r.IsValid)
                    valid++;
                else
                {
                    invalid++;
                    Logger.Warn($"[PacketValidator] {r.ErrorMessage}");
                }
            }
            Logger.Info(
                $"[PacketValidator] Pool '{poolLabel}': {valid}/{pool.Length} valid, {invalid} invalid.");
            return (valid, invalid);
        }

        private static ValidationResult ValidateTcp(
            byte[] f, int ipStart, int ipHLen,
            int tcpStart, int tcpLen, string label)
        {
            if (tcpLen < 20)
                return Fail(label, $"TCP segment too short: {tcpLen} bytes (minimum 20)");

            int dataOffset   = (f[tcpStart + 12] >> 4) & 0xF;
            int tcpHeaderLen = dataOffset * 4;

            if (tcpHeaderLen < 20)
                return Fail(label,
                    $"TCP DataOffset={dataOffset} implies {tcpHeaderLen}-byte header (minimum 5 = 20 bytes)");
            if (tcpHeaderLen > tcpLen)
                return Fail(label,
                    $"TCP DataOffset={dataOffset} ({tcpHeaderLen} bytes) exceeds segment length {tcpLen}");

            if (tcpHeaderLen > 20)
            {
                int optStart = tcpStart + 20;
                int optEnd   = tcpStart + tcpHeaderLen;
                if (optEnd > f.Length)
                    return Fail(label, "TCP options extend beyond the frame boundary");

                var optResult = WalkTcpOptions(f, optStart, tcpHeaderLen - 20, label);
                if (!optResult.IsValid) return optResult;
            }

            return VerifyTransportChecksum(f, ipStart, tcpStart, tcpLen, ProtoTcp, label, "TCP");
        }

        private static ValidationResult WalkTcpOptions(
            byte[] f, int start, int optLen, string label)
        {
            int i   = start;
            int end = start + optLen;

            while (i < end)
            {
                byte kind = f[i];

                if (kind == 0) break;
                if (kind == 1) { i++; continue; }

                if (i + 1 >= end)
                    return Fail(label,
                        $"TCP option kind={kind} at options-offset {i - start} is missing its length byte");

                int len = f[i + 1];
                if (len < 2)
                    return Fail(label,
                        $"TCP option kind={kind} has length={len} (must be ≥ 2)");
                if (i + len > end)
                    return Fail(label,
                        $"TCP option kind={kind} length={len} overflows the options area by {i + len - end} byte(s)");

                i += len;
            }
            return ValidationResult.Ok();
        }

        private static ValidationResult ValidateUdp(
            byte[] f, int ipStart,
            int udpStart, int udpLen, string label)
        {
            if (udpLen < 8)
                return Fail(label, $"UDP segment too short: {udpLen} bytes (minimum 8)");

            int udpLenField = (f[udpStart + 4] << 8) | f[udpStart + 5];
            if (udpLenField != udpLen)
                return Fail(label,
                    $"UDP length field={udpLenField} but IP TotalLength implies {udpLen} bytes for the transport segment");

            if (f[udpStart + 6] == 0 && f[udpStart + 7] == 0)
                return ValidationResult.Ok();

            return VerifyTransportChecksum(f, ipStart, udpStart, udpLen, ProtoUdp, label, "UDP");
        }

        private static ValidationResult ValidateIcmp(
            byte[] f, int icmpStart, int icmpLen, string label)
        {
            if (icmpLen < 8)
                return Fail(label, $"ICMP segment too short: {icmpLen} bytes (minimum 8)");

            byte icmpType = f[icmpStart];
            if (icmpType != 8)
                return Fail(label, $"ICMP type={icmpType} (expected 8 = Echo Request)");

            if (InternetSum16(f, icmpStart, icmpLen) != 0)
                return Fail(label, "ICMP checksum invalid");

            return ValidationResult.Ok();
        }

        private static ValidationResult VerifyTransportChecksum(
            byte[] f, int ipStart, int tStart, int tLen,
            byte proto, string label, string protoName)
        {

            int bufLen = 12 + tLen;
            byte[] buf = new byte[bufLen];

            Buffer.BlockCopy(f, ipStart + 12, buf, 0, 4);
            Buffer.BlockCopy(f, ipStart + 16, buf, 4, 4);
            buf[8]  = 0;
            buf[9]  = proto;
            buf[10] = (byte)(tLen >> 8);
            buf[11] = (byte)tLen;
            Buffer.BlockCopy(f, tStart, buf, 12, tLen);

            if (InternetSum16(buf, 0, bufLen) != 0)
                return Fail(label, $"{protoName} checksum invalid (pseudo-header residual ≠ 0)");

            return ValidationResult.Ok();
        }

        private static ushort InternetSum16(byte[] data, int offset, int length)
        {
            long sum = 0;
            int  end = offset + length;
            int  i   = offset;

            while (i < end - 1)
            {
                sum += (data[i] << 8) | data[i + 1];
                i   += 2;
            }
            if (i < end) sum += data[i] << 8;

            while (sum >> 16 != 0)
                sum = (sum & 0xFFFF) + (sum >> 16);

            return (ushort)~sum;

        }

        public static ValidationResult ValidateRoundtrip(byte[] frame, string label = "")
        {

            var structural = Validate(frame, label);
            if (!structural.IsValid) return structural;

            try
            {
                var parsed = Packet.ParsePacket(LinkLayers.Ethernet, frame);
                if (parsed is not EthernetPacket ethParsed)
                    return Fail(label, "Roundtrip: PacketDotNet could not parse as EthernetPacket");

                if (ethParsed.PayloadPacket is not IPv4Packet ipParsed)
                    return Fail(label, "Roundtrip: Ethernet payload could not be parsed as IPv4Packet");

                int expectedIpTotal = frame.Length - EthLen;
                if (ipParsed.TotalLength != expectedIpTotal)
                    return Fail(label,
                        $"Roundtrip: parsed IP TotalLength={ipParsed.TotalLength} " +
                        $"but expected {expectedIpTotal} (frameLen={frame.Length})");

                byte proto = frame[EthLen + 9];
                switch (proto)
                {
                    case ProtoTcp:
                        if (ipParsed.PayloadPacket is not TcpPacket tcpParsed)
                            return Fail(label, "Roundtrip: IPv4 payload could not be parsed as TcpPacket");

                        int ipHLen    = (frame[EthLen] & 0x0F) * 4;
                        int rawOffset = (frame[EthLen + ipHLen + 12] >> 4) & 0xF;
                        if (tcpParsed.DataOffset != rawOffset)
                            return Fail(label,
                                $"Roundtrip: parsed TCP DataOffset={tcpParsed.DataOffset} " +
                                $"but raw frame byte says {rawOffset}");
                        break;

                    case ProtoUdp:
                        if (ipParsed.PayloadPacket is not UdpPacket)
                            return Fail(label, "Roundtrip: IPv4 payload could not be parsed as UdpPacket");
                        break;

                    case ProtoIcmp:
                        if (ipParsed.PayloadPacket is not IcmpV4Packet)
                            return Fail(label, "Roundtrip: IPv4 payload could not be parsed as IcmpV4Packet");
                        break;
                }

                return ValidationResult.Ok();
            }
            catch (Exception ex)
            {
                return Fail(label, $"Roundtrip: exception during PacketDotNet parsing: {ex.Message}");
            }
        }

        public static (int Valid, int Invalid) ValidatePoolFull(byte[][] pool, string poolLabel)
        {
            int valid   = 0;
            int invalid = 0;

            int catIpLen = 0, catIpCs = 0;
            int catTcpOff = 0, catTcpOpt = 0, catTcpCs = 0;
            int catUdp = 0, catIcmp = 0, catRt = 0, catOther = 0;

            for (int i = 0; i < pool.Length; i++)
            {
                if (pool[i] == null) continue;

                var result = ValidateRoundtrip(pool[i], $"{poolLabel}[{i}]");
                if (result.IsValid)
                {
                    valid++;
                    continue;
                }

                invalid++;
                string msg = result.ErrorMessage;
                Logger.Warn($"[PacketValidator] {msg}");

                if      (msg.Contains("IP header checksum"))                 catIpCs++;
                else if (msg.Contains("TotalLength") || msg.Contains("too short") ||
                         msg.Contains("Frame too short"))                     catIpLen++;
                else if (msg.Contains("DataOffset") && msg.Contains("TCP"))  catTcpOff++;
                else if (msg.Contains("TCP option"))                          catTcpOpt++;
                else if (msg.Contains("TCP checksum"))                        catTcpCs++;
                else if (msg.Contains("UDP"))                                 catUdp++;
                else if (msg.Contains("ICMP"))                                catIcmp++;
                else if (msg.Contains("Roundtrip"))                           catRt++;
                else                                                          catOther++;
            }

            Logger.Info(
                $"[PacketValidator] Pool '{poolLabel}': {valid}/{pool.Length} valid, {invalid} invalid.");

            if (invalid > 0)
                Logger.Warn(
                    $"[PacketValidator] Failure breakdown — " +
                    $"ip_len={catIpLen} ip_checksum={catIpCs} " +
                    $"tcp_offset={catTcpOff} tcp_options={catTcpOpt} tcp_checksum={catTcpCs} " +
                    $"udp={catUdp} icmp={catIcmp} roundtrip={catRt} other={catOther}");

            return (valid, invalid);
        }

        private static ValidationResult Fail(string label, string msg)
        {
            string full = string.IsNullOrEmpty(label) ? msg : $"[{label}] {msg}";
            return ValidationResult.Fail(full);
        }
    }
}
