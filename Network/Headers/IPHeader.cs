using System.Net;
using System.Net.Sockets;

namespace Dorothy.Network.Headers
{
    public class IPHeader
    {
        public byte Version { get; set; }
        public int HeaderLength { get; set; }
        public int TotalLength { get; set; }
        public byte TimeToLive { get; set; }
        public ProtocolType Protocol { get; set; }
        public required IPAddress SourceAddress { get; set; }
        public required IPAddress DestinationAddress { get; set; }
        public ushort Identification { get; set; }
        public required string Flags { get; set; }
        public int FragmentOffset { get; set; }
        public ushort Checksum { get; set; }
    }
} 