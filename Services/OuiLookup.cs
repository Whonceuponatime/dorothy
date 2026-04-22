using System;
using System.Collections.Generic;
using System.IO;

namespace Dorothy.Services
{
    public static class OuiLookup
    {
        private static readonly Lazy<Dictionary<string, string>> _lookup = new Lazy<Dictionary<string, string>>(Load);

        public static string LookupOui(string macOrPrefix)
        {
            if (string.IsNullOrWhiteSpace(macOrPrefix)) return string.Empty;
            var stripped = macOrPrefix.Replace(":", string.Empty).Replace("-", string.Empty).Replace(".", string.Empty);
            if (stripped.Length < 6) return string.Empty;
            var key = stripped.Substring(0, 6).ToUpperInvariant();
            return _lookup.Value.TryGetValue(key, out var v) ? v : string.Empty;
        }

        private static Dictionary<string, string> Load()
        {
            var dict = new Dictionary<string, string>(StringComparer.Ordinal);
            try
            {
                var content = TryReadResource() ?? TryReadDiskFile();
                if (string.IsNullOrEmpty(content)) return dict;

                foreach (var rawLine in content.Split('\n'))
                {
                    var line = rawLine.Trim();
                    if (line.Length == 0 || line.StartsWith("#")) continue;

                    var tab = line.IndexOf('\t');
                    if (tab <= 0) continue;
                    var prefix = line.Substring(0, tab).Replace(":", string.Empty).Replace("-", string.Empty).ToUpperInvariant();
                    if (prefix.Length < 6) continue;
                    var key = prefix.Substring(0, 6);
                    var vendor = line.Substring(tab + 1).Trim();
                    if (vendor.Length > 0) dict[key] = vendor;
                }
            }
            catch
            {
            }
            return dict;
        }

        private static string? TryReadResource()
        {
            try
            {
                var uri = new Uri("pack://application:,,,/Resources/oui.txt", UriKind.Absolute);
                var info = System.Windows.Application.GetResourceStream(uri);
                if (info == null) return null;
                using var reader = new StreamReader(info.Stream);
                return reader.ReadToEnd();
            }
            catch
            {
                return null;
            }
        }

        private static string? TryReadDiskFile()
        {
            try
            {
                var path = Path.Combine(AppContext.BaseDirectory, "Resources", "oui.txt");
                if (File.Exists(path)) return File.ReadAllText(path);
            }
            catch
            {
            }
            return null;
        }
    }
}
