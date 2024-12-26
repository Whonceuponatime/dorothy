using System;
using System.Net;

namespace Dorothy.Models
{
    public class PacketParameters
    {
        public byte[] SourceMac { get; set; } = Array.Empty<byte>();
        public byte[] DestinationMac { get; set; } = Array.Empty<byte>();
        public IPAddress SourceIp { get; set; } = IPAddress.None;
        public IPAddress DestinationIp { get; set; } = IPAddress.None;
        public int SourcePort { get; set; }
        public int DestinationPort { get; set; }
        public long BytesPerSecond { get; set; }
        public byte Ttl { get; set; }
    }
}