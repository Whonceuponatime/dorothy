using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using NLog;

namespace Dorothy.Models
{
    public class NetworkAsset
    {
        public string IpAddress { get; set; } = string.Empty;
        public string MacAddress { get; set; } = string.Empty;
        public string Hostname { get; set; } = string.Empty;
        public string Vendor { get; set; } = string.Empty;
        public bool IsReachable { get; set; }
        public long? RoundTripTime { get; set; }
        public string Status { get; set; } = string.Empty;
    }

    public class NetworkScan
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        private readonly AttackLogger _attackLogger;

        public NetworkScan(AttackLogger attackLogger)
        {
            _attackLogger = attackLogger ?? throw new ArgumentNullException(nameof(attackLogger));
        }

        public async Task<List<NetworkAsset>> ScanNetworkAsync(string networkAddress, string subnetMask, CancellationToken cancellationToken = default)
        {
            var assets = new List<NetworkAsset>();
            
            try
            {
                if (!IPAddress.TryParse(networkAddress, out var networkIp))
                {
                    throw new ArgumentException($"Invalid network address: {networkAddress}");
                }

                if (!IPAddress.TryParse(subnetMask, out var maskIp))
                {
                    throw new ArgumentException($"Invalid subnet mask: {subnetMask}");
                }

                var networkBytes = networkIp.GetAddressBytes();
                var maskBytes = maskIp.GetAddressBytes();
                
                // Calculate network address
                var networkStart = new byte[4];
                for (int i = 0; i < 4; i++)
                {
                    networkStart[i] = (byte)(networkBytes[i] & maskBytes[i]);
                }

                _attackLogger.LogInfo($"🔍 Starting network scan...");
                _attackLogger.LogInfo($"Network: {networkAddress}/{GetCidrNotation(maskBytes)}");
                _attackLogger.LogInfo($"Scanning network range...");

                int totalHosts = CalculateHostCount(maskBytes);
                int scanned = 0;

                // Scan network range (skip network and broadcast addresses)
                for (int i = 1; i < totalHosts - 1; i++)
                {
                    if (cancellationToken.IsCancellationRequested)
                        break;

                    var hostIp = CalculateHostIp(networkStart, i);
                    var ipString = string.Join(".", hostIp);

                    try
                    {
                        var asset = await ScanHostAsync(ipString, cancellationToken);
                        if (asset != null)
                        {
                            assets.Add(asset);
                            _attackLogger.LogSuccess($"✅ Found: {asset.IpAddress} | MAC: {asset.MacAddress} | Hostname: {asset.Hostname}");
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.Debug(ex, $"Error scanning {ipString}");
                    }

                    scanned++;
                    if (scanned % 10 == 0)
                    {
                        _attackLogger.LogInfo($"Scanned {scanned}/{totalHosts - 2} hosts...");
                    }
                }

                _attackLogger.LogSuccess($"✅ Network scan complete. Found {assets.Count} active devices.");
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Network scan failed");
                _attackLogger.LogError($"Network scan failed: {ex.Message}");
                throw;
            }

            return assets;
        }

        private async Task<NetworkAsset?> ScanHostAsync(string ipAddress, CancellationToken cancellationToken)
        {
            try
            {
                // Ping the host first
                using var ping = new Ping();
                var reply = await ping.SendPingAsync(ipAddress, 1000);
                
                if (reply.Status != IPStatus.Success)
                {
                    return null; // Host is not reachable
                }

                var asset = new NetworkAsset
                {
                    IpAddress = ipAddress,
                    IsReachable = true,
                    RoundTripTime = reply.RoundtripTime,
                    Status = "Online"
                };

                // Get MAC address
                try
                {
                    var macBytes = await GetMacAddressAsync(ipAddress);
                    if (macBytes.Length == 6)
                    {
                        asset.MacAddress = BitConverter.ToString(macBytes).Replace("-", ":");
                        asset.Vendor = GetVendorFromMac(asset.MacAddress);
                    }
                }
                catch
                {
                    asset.MacAddress = "Unknown";
                }

                // Get hostname
                try
                {
                    var hostEntry = await Dns.GetHostEntryAsync(ipAddress);
                    asset.Hostname = hostEntry.HostName;
                }
                catch
                {
                    asset.Hostname = "Unknown";
                }

                return asset;
            }
            catch
            {
                return null;
            }
        }

        private async Task<byte[]> GetMacAddressAsync(string ipAddress)
        {
            try
            {
                // Try ARP table first
                var arpEntry = await GetArpEntryAsync(ipAddress);
                if (arpEntry != null)
                {
                    return ParseMacAddress(arpEntry);
                }

                // If not in ARP table, try ARP request
                using var ping = new Ping();
                await ping.SendPingAsync(ipAddress, 1000);
                
                // Wait a bit for ARP to populate
                await Task.Delay(100);
                
                arpEntry = await GetArpEntryAsync(ipAddress);
                if (arpEntry != null)
                {
                    return ParseMacAddress(arpEntry);
                }

                return Array.Empty<byte>();
            }
            catch
            {
                return Array.Empty<byte>();
            }
        }

        private async Task<string?> GetArpEntryAsync(string ipAddress)
        {
            try
            {
                using var process = new System.Diagnostics.Process
                {
                    StartInfo = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "arp",
                        Arguments = $"-a {ipAddress}",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                string output = await process.StandardOutput.ReadToEndAsync();
                await process.WaitForExitAsync();

                var match = System.Text.RegularExpressions.Regex.Match(output, @"([0-9A-F]{2}[:-]){5}([0-9A-F]{2})", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                return match.Success ? match.Value : null;
            }
            catch
            {
                return null;
            }
        }

        private byte[] ParseMacAddress(string macAddress)
        {
            string cleanMac = macAddress.Replace(":", "").Replace("-", "");
            if (cleanMac.Length != 12)
            {
                throw new ArgumentException("Invalid MAC address format");
            }

            byte[] macBytes = new byte[6];
            for (int i = 0; i < 6; i++)
            {
                macBytes[i] = Convert.ToByte(cleanMac.Substring(i * 2, 2), 16);
            }
            return macBytes;
        }

        private string GetVendorFromMac(string macAddress)
        {
            // Extract first 3 octets (OUI - Organizationally Unique Identifier)
            var parts = macAddress.Split(':');
            if (parts.Length >= 3)
            {
                var oui = $"{parts[0]}:{parts[1]}:{parts[2]}".ToUpper();
                // Common vendor OUIs (simplified - in production, use a full OUI database)
                switch (oui)
                {
                    case "00:50:56":
                    case "00:0C:29":
                        return "VMware";
                    case "00:1C:14":
                    case "00:1E:67":
                        return "Dell";
                    case "00:21:70":
                    case "00:23:24":
                        return "HP";
                    case "00:25:90":
                    case "00:26:BB":
                        return "Apple";
                    default:
                        return "Unknown";
                }
            }
            return "Unknown";
        }

        private byte[] CalculateHostIp(byte[] networkStart, int hostIndex)
        {
            var ip = new byte[4];
            Array.Copy(networkStart, ip, 4);
            
            int carry = hostIndex;
            for (int i = 3; i >= 0 && carry > 0; i--)
            {
                int sum = ip[i] + carry;
                ip[i] = (byte)(sum % 256);
                carry = sum / 256;
            }
            
            return ip;
        }

        private int CalculateHostCount(byte[] maskBytes)
        {
            int hostBits = 0;
            foreach (var b in maskBytes)
            {
                hostBits += CountZeroBits(b);
            }
            return (int)Math.Pow(2, hostBits);
        }

        private int CountZeroBits(byte b)
        {
            int count = 0;
            for (int i = 0; i < 8; i++)
            {
                if ((b & (1 << i)) == 0)
                    count++;
            }
            return count;
        }

        private int GetCidrNotation(byte[] maskBytes)
        {
            int cidr = 0;
            foreach (var b in maskBytes)
            {
                cidr += CountOneBits(b);
            }
            return cidr;
        }

        private int CountOneBits(byte b)
        {
            int count = 0;
            for (int i = 0; i < 8; i++)
            {
                if ((b & (1 << i)) != 0)
                    count++;
            }
            return count;
        }
    }
}

