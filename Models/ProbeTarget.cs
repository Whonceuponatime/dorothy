using System.Collections.Generic;

namespace Dorothy.Models
{
    public class ProbeTarget
    {
        public string Raw { get; set; } = string.Empty;
        public List<string> ExpandedIps { get; set; } = new List<string>();

        public bool RunRouteCheck { get; set; } = true;
        public bool RunIcmpPing { get; set; } = true;
        public bool RunTraceroute { get; set; } = true;
        public bool RunTcpTraceroute { get; set; } = false;
        public bool RunTcpScan { get; set; } = true;
        public bool RunSnmpProbe { get; set; } = false;

        public List<int> TcpPorts { get; set; } = new List<int> { 22, 23, 80, 443, 3389, 8080, 8443, 161 };
        public string SnmpCommunity { get; set; } = "public";
    }
}
