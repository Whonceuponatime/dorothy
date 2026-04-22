namespace Dorothy.Models
{
    public class TracerouteHop
    {
        public int HopNumber { get; set; }
        public string? IpAddress { get; set; }
        public string? Hostname { get; set; }
        public long? RttMs { get; set; }
        public bool NoReply { get; set; }

        public string Display
        {
            get
            {
                if (NoReply)
                {
                    return $"{HopNumber,2}  * * *";
                }
                var host = string.IsNullOrEmpty(Hostname) ? IpAddress : $"{Hostname} [{IpAddress}]";
                var rtt = RttMs.HasValue ? $"{RttMs} ms" : "-";
                return $"{HopNumber,2}  {rtt}  {host}";
            }
        }
    }
}
