namespace Dorothy.Models
{
    public static class ProbeLevelDisplay
    {
        public static string ToDisplayName(this ProbeLevel level)
        {
            return level switch
            {
                ProbeLevel.Survey   => "Reachability test",
                ProbeLevel.Simple   => "Banner grab",
                ProbeLevel.Advanced => "Deep scan",
                _ => level.ToString()
            };
        }

        public static string ToShortName(this ProbeLevel level)
        {
            return level switch
            {
                ProbeLevel.Survey   => "Reach",
                ProbeLevel.Simple   => "Banner",
                ProbeLevel.Advanced => "Deep",
                _ => level.ToString()
            };
        }
    }
}
