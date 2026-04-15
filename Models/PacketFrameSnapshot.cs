using System;
using System.Collections.Generic;

namespace Dorothy.Models
{
    public class PacketFrameSnapshot
    {
        public string AttackType { get; set; } = string.Empty;
        public int FrameSizeBytes { get; set; }
        public double TargetMbps { get; set; }
        public string InjectionMode { get; set; } = string.Empty;
        public List<PacketLayer> Layers { get; set; } = new();
        public byte[] RawBytes { get; set; } = Array.Empty<byte>();
        public int[] ByteLayerMap { get; set; } = Array.Empty<int>();

        public static PacketFrameSnapshot FromPacket(
            byte[] frame, string attackType, double targetMbps, string injectionMode)
        {
            var snap = new PacketFrameSnapshot
            {
                AttackType = attackType,
                FrameSizeBytes = frame.Length,
                TargetMbps = targetMbps,
                InjectionMode = injectionMode,
                RawBytes = (byte[])frame.Clone()
            };

            var layers = new List<PacketLayer>();
            var byteMap = new int[frame.Length];
            int offset = 0;

            // --- Ethernet II (14 bytes) ---
            if (frame.Length < 14) { snap.Layers = layers; snap.ByteLayerMap = byteMap; return snap; }

            int ethIdx = layers.Count;
            var ethLayer = new PacketLayer
            {
                Name = "Ethernet II",
                ByteCount = 14,
                ColorKey = "Ethernet",
                Fields = new List<(string, string)>
                {
                    ("Dst MAC", FormatMac(frame, 0)),
                    ("Src MAC", FormatMac(frame, 6)),
                    ("EtherType", $"0x{frame[12]:X2}{frame[13]:X2}")
                }
            };
            layers.Add(ethLayer);
            FillMap(byteMap, 0, 14, ethIdx);
            offset = 14;

            ushort etherType = (ushort)((frame[12] << 8) | frame[13]);
            if (etherType != 0x0800 || frame.Length < offset + 20)
            {
                AddPayloadLayer(layers, byteMap, offset, frame.Length - offset);
                snap.Layers = layers; snap.ByteLayerMap = byteMap; return snap;
            }

            // --- IPv4 ---
            int ipStart = offset;
            int ihl = (frame[ipStart] & 0x0F) * 4;
            if (ihl < 20 || frame.Length < ipStart + ihl)
            {
                AddPayloadLayer(layers, byteMap, offset, frame.Length - offset);
                snap.Layers = layers; snap.ByteLayerMap = byteMap; return snap;
            }

            int ipTotal = (frame[ipStart + 2] << 8) | frame[ipStart + 3];
            byte protocol = frame[ipStart + 9];
            int ipIdx = layers.Count;

            var ipLayer = new PacketLayer
            {
                Name = "IPv4",
                ByteCount = ihl,
                ColorKey = "IP",
                Fields = new List<(string, string)>
                {
                    ("Src", FormatIp(frame, ipStart + 12)),
                    ("Dst", FormatIp(frame, ipStart + 16)),
                    ("TTL", frame[ipStart + 8].ToString()),
                    ("IP ID", $"0x{frame[ipStart + 4]:X2}{frame[ipStart + 5]:X2}"),
                    ("Protocol", protocol.ToString()),
                    ("Total Len", ipTotal.ToString())
                }
            };
            layers.Add(ipLayer);
            FillMap(byteMap, ipStart, ihl, ipIdx);
            offset = ipStart + ihl;

            // --- Transport layer ---
            int transportLen = ipTotal - ihl;
            if (transportLen < 0) transportLen = 0;
            int transportEnd = ipStart + ipTotal;
            if (transportEnd > frame.Length) transportEnd = frame.Length;

            if (protocol == 6 && transportLen >= 20)
            {
                // TCP
                int tcpStart = offset;
                int dataOffset = ((frame[tcpStart + 12] >> 4) & 0x0F) * 4;
                if (dataOffset < 20) dataOffset = 20;
                int tcpHeaderLen = Math.Min(dataOffset, transportEnd - tcpStart);
                int tcpIdx = layers.Count;

                ushort srcPort = (ushort)((frame[tcpStart] << 8) | frame[tcpStart + 1]);
                ushort dstPort = (ushort)((frame[tcpStart + 2] << 8) | frame[tcpStart + 3]);
                uint seq = (uint)((frame[tcpStart + 4] << 24) | (frame[tcpStart + 5] << 16) |
                                  (frame[tcpStart + 6] << 8) | frame[tcpStart + 7]);
                byte flags = frame[tcpStart + 13];
                ushort window = (ushort)((frame[tcpStart + 14] << 8) | frame[tcpStart + 15]);

                var tcpLayer = new PacketLayer
                {
                    Name = "TCP",
                    ByteCount = tcpHeaderLen,
                    ColorKey = "TCP",
                    Fields = new List<(string, string)>
                    {
                        ("Src Port", srcPort.ToString()),
                        ("Dst Port", dstPort.ToString()),
                        ("Flags", FormatTcpFlags(flags)),
                        ("Seq", $"0x{seq:X8}"),
                        ("Window", window.ToString()),
                        ("Data Offset", $"{dataOffset}B")
                    }
                };
                layers.Add(tcpLayer);
                FillMap(byteMap, tcpStart, tcpHeaderLen, tcpIdx);
                offset = tcpStart + tcpHeaderLen;
            }
            else if (protocol == 17 && transportLen >= 8)
            {
                // UDP
                int udpStart = offset;
                int udpIdx = layers.Count;

                ushort srcPort = (ushort)((frame[udpStart] << 8) | frame[udpStart + 1]);
                ushort dstPort = (ushort)((frame[udpStart + 2] << 8) | frame[udpStart + 3]);
                ushort udpLen = (ushort)((frame[udpStart + 4] << 8) | frame[udpStart + 5]);

                var udpLayer = new PacketLayer
                {
                    Name = "UDP",
                    ByteCount = 8,
                    ColorKey = "UDP",
                    Fields = new List<(string, string)>
                    {
                        ("Src Port", srcPort.ToString()),
                        ("Dst Port", dstPort.ToString()),
                        ("Length", udpLen.ToString())
                    }
                };
                layers.Add(udpLayer);
                FillMap(byteMap, udpStart, 8, udpIdx);
                offset = udpStart + 8;
            }
            else if (protocol == 1 && transportLen >= 8)
            {
                // ICMP
                int icmpStart = offset;
                int icmpIdx = layers.Count;
                int icmpLen = transportEnd - icmpStart;

                byte type = frame[icmpStart];
                byte code = frame[icmpStart + 1];
                ushort id = (ushort)((frame[icmpStart + 4] << 8) | frame[icmpStart + 5]);
                ushort seqNum = (ushort)((frame[icmpStart + 6] << 8) | frame[icmpStart + 7]);

                var icmpLayer = new PacketLayer
                {
                    Name = "ICMP",
                    ByteCount = icmpLen,
                    ColorKey = "ICMP",
                    Fields = new List<(string, string)>
                    {
                        ("Type", type.ToString()),
                        ("Code", code.ToString()),
                        ("ID", $"0x{id:X4}"),
                        ("Seq", seqNum.ToString())
                    }
                };
                layers.Add(icmpLayer);
                FillMap(byteMap, icmpStart, icmpLen, icmpIdx);
                offset = icmpStart + icmpLen;
            }
            else
            {
                AddPayloadLayer(layers, byteMap, offset, transportEnd - offset);
                offset = transportEnd;
            }

            // --- Remaining payload ---
            if (offset < frame.Length)
                AddPayloadLayer(layers, byteMap, offset, frame.Length - offset);

            snap.Layers = layers;
            snap.ByteLayerMap = byteMap;
            return snap;
        }

        private static void AddPayloadLayer(List<PacketLayer> layers, int[] map, int start, int length)
        {
            if (length <= 0) return;
            int idx = layers.Count;
            layers.Add(new PacketLayer
            {
                Name = "Payload",
                ByteCount = length,
                ColorKey = "Payload",
                Fields = new List<(string, string)> { ("Size", $"{length} bytes") }
            });
            FillMap(map, start, length, idx);
        }

        private static void FillMap(int[] map, int start, int length, int layerIndex)
        {
            int end = Math.Min(start + length, map.Length);
            for (int i = start; i < end; i++) map[i] = layerIndex;
        }

        private static string FormatMac(byte[] data, int offset)
            => $"{data[offset]:X2}:{data[offset + 1]:X2}:{data[offset + 2]:X2}:" +
               $"{data[offset + 3]:X2}:{data[offset + 4]:X2}:{data[offset + 5]:X2}";

        private static string FormatIp(byte[] data, int offset)
            => $"{data[offset]}.{data[offset + 1]}.{data[offset + 2]}.{data[offset + 3]}";

        private static string FormatTcpFlags(byte flags)
        {
            var parts = new List<string>(4);
            if ((flags & 0x02) != 0) parts.Add("SYN");
            if ((flags & 0x10) != 0) parts.Add("ACK");
            if ((flags & 0x01) != 0) parts.Add("FIN");
            if ((flags & 0x04) != 0) parts.Add("RST");
            if ((flags & 0x08) != 0) parts.Add("PSH");
            if ((flags & 0x20) != 0) parts.Add("URG");
            return parts.Count > 0 ? string.Join(" | ", parts) : $"0x{flags:X2}";
        }
    }
}
