namespace Dorothy.Network.Headers
{
    public class IcmpHeader
    {
        public byte Type { get; set; }
        public byte Code { get; set; }
        public ushort Checksum { get; set; }
        public ushort Identifier { get; set; }
        public ushort SequenceNumber { get; set; }
    }
} 