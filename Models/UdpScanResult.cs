namespace Dorothy.Models
{
    public enum UdpStatus
    {
        Open,            // got a UDP response on this port
        OpenOrFiltered,  // no response, no ICMP unreachable — could be either
        Closed           // got ICMP port unreachable
    }

    public record UdpScanResult(
        int Port,
        UdpStatus Status,
        string? RawBanner,
        string? IdentifiedService);
}
