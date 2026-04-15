namespace Dorothy.Services
{

    public sealed class FloodOptions
    {

        public bool FirewallBypassMode { get; init; }

        public bool ForceSoftwareChecksum { get; init; }

        public bool UseRealSourceIp { get; init; }

        public bool RandomizeWithinSubnet { get; init; }
    }
}
