namespace Dorothy.Models
{
    public enum ProbeStatus
    {
        Pending,
        Running,
        Reachable,
        Partial,
        Unreachable,
        NoRoute,
        Error
    }

    public enum PortStatus
    {
        Open,
        Closed,
        Filtered,
        Error
    }

    public enum IcmpStatus
    {
        Reply,
        NoReply,
        Error
    }

    public enum RouteStatus
    {
        Local,
        ViaGateway,
        NoRoute,
        Unknown
    }
}
