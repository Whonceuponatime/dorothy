namespace Dorothy.Network.Headers
{
    public class TcpHeader
    {
        public ushort SourcePort { get; set; }
        public ushort DestinationPort { get; set; }
        public uint SequenceNumber { get; set; }
        public uint AcknowledgmentNumber { get; set; }
        public int HeaderLength { get; set; }
        public required string Flags { get; set; }
        public ushort WindowSize { get; set; }
        public ushort Checksum { get; set; }
        public ushort UrgentPointer { get; set; }
    }
} 