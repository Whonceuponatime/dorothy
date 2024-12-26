using System;
using Dorothy.Network.Headers;

namespace Dorothy.Network
{
    public class PacketEventArgs : EventArgs
    {
        public IPHeader IpHeader { get; }
        public TcpHeader? TcpHeader { get; }
        public IcmpHeader? IcmpHeader { get; }

        public PacketEventArgs(IPHeader ipHeader, TcpHeader? tcpHeader = null, IcmpHeader? icmpHeader = null)
        {
            IpHeader = ipHeader;
            TcpHeader = tcpHeader;
            IcmpHeader = icmpHeader;
        }
    }
} 