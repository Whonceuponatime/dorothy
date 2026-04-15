using System;
using System.Collections.Generic;
using System.IO;

namespace Dorothy.Services
{

    internal static class SeacureConfig
    {
        private const string DefaultApiUrl = "https://api.seacuredb.com";

        private static readonly Lazy<Dictionary<string, string>> _env =
            new(LoadDotEnv, isThreadSafe: true);

        public static string ApiUrl => Get("SEACUREDB_API_URL") ?? DefaultApiUrl;
        public static string? Email => Get("SEACUREDB_EMAIL");
        public static string? Password => Get("SEACUREDB_PASSWORD");

        public static bool IsConfigured =>
            !string.IsNullOrWhiteSpace(Email) && !string.IsNullOrWhiteSpace(Password);

        private static string? Get(string key)
        {
            var fromEnv = Environment.GetEnvironmentVariable(key);
            if (!string.IsNullOrWhiteSpace(fromEnv)) return fromEnv;
            return _env.Value.TryGetValue(key, out var v) && !string.IsNullOrWhiteSpace(v) ? v : null;
        }

        private static Dictionary<string, string> LoadDotEnv()
        {
            var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var path in CandidateEnvPaths())
            {
                if (!File.Exists(path)) continue;
                try
                {
                    foreach (var raw in File.ReadAllLines(path))
                    {
                        var line = raw.Trim();
                        if (line.Length == 0 || line.StartsWith("#")) continue;
                        var eq = line.IndexOf('=');
                        if (eq < 1) continue;
                        var key = line.Substring(0, eq).Trim();
                        var val = line.Substring(eq + 1).Trim();
                        if (val.Length >= 2 &&
                            ((val[0] == '"'  && val[^1] == '"') ||
                             (val[0] == '\'' && val[^1] == '\'')))
                            val = val.Substring(1, val.Length - 2);
                        dict[key] = val;
                    }
                    break;
                }
                catch {  }
            }
            return dict;
        }

        private static IEnumerable<string> CandidateEnvPaths()
        {
            yield return Path.Combine(AppContext.BaseDirectory, ".env");

            var dir = new DirectoryInfo(AppContext.BaseDirectory);
            for (int i = 0; i < 6 && dir is not null; i++, dir = dir.Parent)
                yield return Path.Combine(dir.FullName, ".env");
        }
    }
}
