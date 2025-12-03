namespace Dorothy.Models
{
    public enum AttackType
    {
        UdpFlood,
        TcpSynFlood,
        IcmpFlood,
        TcpRoutedFlood,
        Broadcast,
        ArpSpoof
    }
    public enum AdvancedAttackType
    {
        ArpSpoof,
        MacFlood,
        UdpFlood,
        TcpSynFlood,
        IcmpFlood,
        TcpRoutedFlood,
        EthernetUnicast,
        EthernetMulticast,
        EthernetBroadcast,
        Nmea0183UdpUnicast,
        Nmea0183UdpMulticast
    }
}