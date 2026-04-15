using System.Collections.Generic;

namespace Dorothy.Models
{
    public class PacketLayer
    {
        public string Name { get; set; } = string.Empty;
        public int ByteCount { get; set; }
        public string ColorKey { get; set; } = string.Empty;
        public List<(string Field, string Value)> Fields { get; set; } = new();
    }
}
