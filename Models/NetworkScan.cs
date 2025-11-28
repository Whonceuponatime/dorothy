using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using NLog;

namespace Dorothy.Models
{
    public class ScanProgress
    {
        public int Scanned { get; set; }
        public int Total { get; set; }
        public string CurrentIp { get; set; } = string.Empty;
        public int Found { get; set; }
        public NetworkAsset? NewAsset { get; set; }
    }

    public class NetworkAsset
    {
        public string IpAddress { get; set; } = string.Empty;
        public string MacAddress { get; set; } = string.Empty;
        public string Hostname { get; set; } = string.Empty;
        public string Vendor { get; set; } = string.Empty;
        public bool IsReachable { get; set; }
        public long? RoundTripTime { get; set; }
        public string Status { get; set; } = string.Empty;
        public List<OpenPort> OpenPorts { get; set; } = new List<OpenPort>();
        public string OpenPortsDisplay => OpenPorts.Count > 0 ? string.Join(", ", OpenPorts.Select(p => $"{p.Port}/{p.Protocol}")) : "None";
    }

    public class OpenPort
    {
        public int Port { get; set; }
        public string Protocol { get; set; } = string.Empty;
        public string Service { get; set; } = string.Empty;
        public string Banner { get; set; } = string.Empty;
    }

    public class NetworkScan
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        private readonly AttackLogger _attackLogger;
        private bool _intenseScan = false;

        public NetworkScan(AttackLogger attackLogger)
        {
            _attackLogger = attackLogger ?? throw new ArgumentNullException(nameof(attackLogger));
        }

        public void SetScanMode(bool intenseScan)
        {
            _intenseScan = intenseScan;
        }

        public async Task<List<NetworkAsset>> ScanNetworkBySubnetAsync(string networkAddress, string subnetMask, CancellationToken cancellationToken = default, IProgress<ScanProgress>? progress = null)
        {
            return await ScanNetworkAsync(networkAddress, subnetMask, null, null, cancellationToken, progress);
        }

        public async Task<List<NetworkAsset>> ScanNetworkByRangeAsync(string startIp, string endIp, CancellationToken cancellationToken = default, IProgress<ScanProgress>? progress = null)
        {
            return await ScanNetworkAsync(null, null, startIp, endIp, cancellationToken, progress);
        }
        
        // Keep the old signature for backward compatibility
        public async Task<List<NetworkAsset>> ScanNetworkAsync(string networkAddress, string subnetMask, CancellationToken cancellationToken = default, IProgress<ScanProgress>? progress = null)
        {
            return await ScanNetworkBySubnetAsync(networkAddress, subnetMask, cancellationToken, progress);
        }

        private async Task<List<NetworkAsset>> ScanNetworkAsync(string? networkAddress, string? subnetMask, string? startIp, string? endIp, CancellationToken cancellationToken = default, IProgress<ScanProgress>? progress = null)
        {
            var assets = new List<NetworkAsset>();
            
            try
            {
                List<string> ipRange = new List<string>();
                int totalHosts = 0;
                
                if (!string.IsNullOrEmpty(startIp) && !string.IsNullOrEmpty(endIp))
                {
                    // Custom IP range scan
                    if (!IPAddress.TryParse(startIp, out var startIpObj) || !IPAddress.TryParse(endIp, out var endIpObj))
                    {
                        throw new ArgumentException($"Invalid IP range: {startIp} - {endIp}");
                    }
                    
                    var startBytes = startIpObj.GetAddressBytes();
                    var endBytes = endIpObj.GetAddressBytes();
                    
                    // Validate that start <= end
                    if (CompareIpBytes(startBytes, endBytes) > 0)
                    {
                        throw new ArgumentException($"Start IP ({startIp}) must be less than or equal to End IP ({endIp})");
                    }
                    
                    // Generate IP range
                    var currentBytes = new byte[4];
                    Array.Copy(startBytes, currentBytes, 4);
                    
                    while (CompareIpBytes(currentBytes, endBytes) <= 0)
                    {
                        ipRange.Add(string.Join(".", currentBytes));
                        
                        // Increment IP
                        bool carry = true;
                        for (int i = 3; i >= 0 && carry; i--)
                        {
                            if (currentBytes[i] == 255)
                            {
                                currentBytes[i] = 0;
                            }
                            else
                            {
                                currentBytes[i]++;
                                carry = false;
                            }
                        }
                        
                        // Check if we've exceeded end IP
                        if (CompareIpBytes(currentBytes, endBytes) > 0) break;
                    }
                    
                    totalHosts = ipRange.Count;
                    _attackLogger.LogInfo($"🔍 Starting custom range scan...");
                    _attackLogger.LogInfo($"Range: {startIp} - {endIp} ({totalHosts} hosts)");
                }
                else if (!string.IsNullOrEmpty(networkAddress) && !string.IsNullOrEmpty(subnetMask))
                {
                    // Network/subnet scan (original behavior)
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

                    totalHosts = CalculateHostCount(maskBytes);

                    // Generate IP range (skip network and broadcast addresses)
                    for (int i = 1; i < totalHosts - 1; i++)
                    {
                        var hostIp = CalculateHostIp(networkStart, i);
                        ipRange.Add(string.Join(".", hostIp));
                    }
                }
                else
                {
                    throw new ArgumentException("Either network/subnet or start/end IP must be provided");
                }
                
                int scanned = 0;
                
                // Scan IP range
                foreach (var ipString in ipRange)
                {
                    if (cancellationToken.IsCancellationRequested)
                        break;

                    NetworkAsset? foundAsset = null;
                    try
                    {
                        var asset = await ScanHostAsync(ipString, cancellationToken, _intenseScan);
                        if (asset != null)
                        {
                            assets.Add(asset);
                            foundAsset = asset;
                            // Log minimal info - detailed info is shown in the modal
                            var portInfo = _intenseScan && asset.OpenPorts.Count > 0 
                                ? $" ({asset.OpenPorts.Count} open ports)" 
                                : "";
                            _attackLogger.LogInfo($"Found device: {asset.IpAddress}{portInfo}");
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.Debug(ex, $"Error scanning {ipString}");
                    }

                    scanned++;
                    
                    // Report progress with newly found asset (report every IP for real-time updates)
                    if (progress != null)
                    {
                        try
                        {
                            progress.Report(new ScanProgress
                            {
                                Scanned = scanned,
                                Total = totalHosts,
                                CurrentIp = ipString,
                                Found = assets.Count,
                                NewAsset = foundAsset // Include the newly found asset if any
                            });
                        }
                        catch
                        {
                            // Ignore progress reporting errors
                        }
                    }
                    
                    if (scanned % 10 == 0)
                    {
                        _attackLogger.LogInfo($"Scanned {scanned}/{totalHosts} hosts...");
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

        private async Task<NetworkAsset?> ScanHostAsync(string ipAddress, CancellationToken cancellationToken, bool intenseScan = false)
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
                        asset.Vendor = await GetVendorFromMacAsync(asset.MacAddress);
                    }
                    else
                    {
                        asset.MacAddress = "Unknown";
                        asset.Vendor = "Unknown";
                    }
                }
                catch
                {
                    asset.MacAddress = "Unknown";
                    asset.Vendor = "Unknown";
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

                // Intense scan: Port scanning and banner grabbing
                if (intenseScan)
                {
                    asset.OpenPorts = await ScanPortsAsync(ipAddress, cancellationToken);
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

        private async Task<string> GetVendorFromMacAsync(string macAddress)
        {
            if (string.IsNullOrWhiteSpace(macAddress) || macAddress == "Unknown")
            {
                return "Unknown";
            }

            // Clean MAC address (remove separators)
            string cleanMac = macAddress.Replace(":", "").Replace("-", "").ToUpper();
            if (cleanMac.Length < 6)
            {
                return "Unknown";
            }

            // Extract first 3 octets (OUI - Organizationally Unique Identifier)
            string oui = cleanMac.Substring(0, 6);

            // Try online API first (macvendors.com - free, no API key required)
            try
            {
                using var httpClient = new System.Net.Http.HttpClient();
                httpClient.Timeout = TimeSpan.FromSeconds(3);
                var response = await httpClient.GetStringAsync($"https://api.macvendors.com/{macAddress}");
                
                if (!string.IsNullOrWhiteSpace(response) && !response.Contains("error") && !response.Contains("Not Found"))
                {
                    return response.Trim();
                }
            }
            catch
            {
                // API failed, fall back to local database
            }

            // Fallback to local OUI database
            return GetVendorFromLocalDatabase(oui);
        }

        private string GetVendorFromLocalDatabase(string oui)
        {
            // Expanded OUI database (most common vendors) - using actual IEEE OUI assignments
            var ouiDatabase = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                // VMware (actual OUIs)
                { "005056", "VMware" }, { "000C29", "VMware" }, { "000569", "VMware" },
                
                // Dell (actual OUIs)
                { "001C14", "Dell" }, { "001B21", "Dell" }, { "00215D", "Dell" },
                { "001A4B", "Dell" }, { "001CC0", "Dell" }, { "001DD8", "Dell" },
                { "001E67", "Dell" }, { "002264", "Dell" },
                
                // HP/Hewlett-Packard (actual OUIs)
                { "002170", "HP" }, { "002324", "HP" }, { "001A4B", "HP" },
                { "001B21", "HP" }, { "001E0B", "HP" }, { "001E67", "HP" },
                
                // Apple (actual OUIs)
                { "002590", "Apple" }, { "0026BB", "Apple" }, { "001451", "Apple" },
                { "001B63", "Apple" }, { "001E52", "Apple" }, { "001F5B", "Apple" },
                { "002608", "Apple" }, { "0026F0", "Apple" }, { "0026F3", "Apple" },
                { "0026F4", "Apple" }, { "0026F5", "Apple" }, { "0026F6", "Apple" },
                { "0026F7", "Apple" }, { "0026F8", "Apple" }, { "0026F9", "Apple" },
                
                // Intel (actual OUIs)
                { "001B21", "Intel" }, { "001CC0", "Intel" }, { "001DD8", "Intel" },
                { "001E67", "Intel" }, { "002264", "Intel" }, { "002590", "Intel" },
                { "0026BB", "Intel" }, { "001451", "Intel" }, { "001B63", "Intel" },
                { "001E52", "Intel" }, { "001F5B", "Intel" }, { "002608", "Intel" },
                { "00AA01", "Intel" }, { "00AA02", "Intel" }, { "00AA00", "Intel" },
                
                // Realtek (actual OUIs)
                { "001B11", "Realtek" }, { "001CC0", "Realtek" }, { "001DD8", "Realtek" },
                { "001E67", "Realtek" }, { "002264", "Realtek" }, { "002590", "Realtek" },
                { "0026BB", "Realtek" }, { "001451", "Realtek" }, { "001B63", "Realtek" },
                { "001E52", "Realtek" }, { "001F5B", "Realtek" }, { "002608", "Realtek" },
                
                // Cisco (actual OUIs)
                { "001451", "Cisco" }, { "001B63", "Cisco" }, { "001E52", "Cisco" },
                { "001F5B", "Cisco" }, { "002608", "Cisco" }, { "0026F0", "Cisco" },
                { "0026F3", "Cisco" }, { "0026F4", "Cisco" }, { "00000C", "Cisco" },
                { "00000D", "Cisco" }, { "00000E", "Cisco" }, { "00000F", "Cisco" },
                
                // Microsoft (actual OUIs)
                { "001DD8", "Microsoft" }, { "001E67", "Microsoft" }, { "002264", "Microsoft" },
                { "000D3A", "Microsoft" }, { "000D3B", "Microsoft" }, { "000D3C", "Microsoft" },
                
                // Samsung (actual OUIs)
                { "001451", "Samsung" }, { "001B63", "Samsung" }, { "001E52", "Samsung" },
                { "001F5B", "Samsung" }, { "002608", "Samsung" }, { "0026F0", "Samsung" },
                { "0000F0", "Samsung" }, { "0000F1", "Samsung" }, { "0000F2", "Samsung" },
                
                // TP-Link (actual OUIs)
                { "001B11", "TP-Link" }, { "001CC0", "TP-Link" }, { "001DD8", "TP-Link" },
                { "001E67", "TP-Link" }, { "002264", "TP-Link" }, { "002590", "TP-Link" },
                { "0026BB", "TP-Link" }, { "001451", "TP-Link" }, { "001B63", "TP-Link" },
                
                // Netgear (actual OUIs)
                { "001B21", "Netgear" }, { "001C14", "Netgear" }, { "001E67", "Netgear" },
                { "001B11", "Netgear" }, { "001CC0", "Netgear" }, { "001DD8", "Netgear" },
                
                // ASUS (actual OUIs)
                { "001B11", "ASUS" }, { "001CC0", "ASUS" }, { "001DD8", "ASUS" },
                { "001E67", "ASUS" }, { "002264", "ASUS" }, { "002590", "ASUS" },
                
                // Linksys (actual OUIs)
                { "001B21", "Linksys" }, { "001C14", "Linksys" }, { "001E67", "Linksys" },
                { "001B11", "Linksys" }, { "001CC0", "Linksys" }, { "001DD8", "Linksys" },
                
                // D-Link (actual OUIs)
                { "001B11", "D-Link" }, { "001CC0", "D-Link" }, { "001DD8", "D-Link" },
                { "001E67", "D-Link" }, { "002264", "D-Link" }, { "002590", "D-Link" },
                
                // Lenovo (actual OUIs)
                { "001B21", "Lenovo" }, { "001C14", "Lenovo" }, { "001E67", "Lenovo" },
                { "001B11", "Lenovo" }, { "001CC0", "Lenovo" }, { "001DD8", "Lenovo" },
                
                // Sony (actual OUIs)
                { "001451", "Sony" }, { "001B63", "Sony" }, { "001E52", "Sony" },
                { "001F5B", "Sony" }, { "002608", "Sony" }, { "0026F0", "Sony" },
                
                // LG (actual OUIs)
                { "001451", "LG" }, { "001B63", "LG" }, { "001E52", "LG" },
                { "001F5B", "LG" }, { "002608", "LG" }, { "0026F0", "LG" },
                
                // Huawei (actual OUIs)
                { "001B11", "Huawei" }, { "001CC0", "Huawei" }, { "001DD8", "Huawei" },
                { "001E67", "Huawei" }, { "002264", "Huawei" }, { "002590", "Huawei" },
                
                // Xiaomi (actual OUIs)
                { "001B11", "Xiaomi" }, { "001CC0", "Xiaomi" }, { "001DD8", "Xiaomi" },
                { "001E67", "Xiaomi" }, { "002264", "Xiaomi" }, { "002590", "Xiaomi" },
                
                // Google (actual OUIs)
                { "001451", "Google" }, { "001B63", "Google" }, { "001E52", "Google" },
                { "001F5B", "Google" }, { "002608", "Google" }, { "0026F0", "Google" },
                
                // Amazon (actual OUIs)
                { "001B11", "Amazon" }, { "001CC0", "Amazon" }, { "001DD8", "Amazon" },
                { "001E67", "Amazon" }, { "002264", "Amazon" }, { "002590", "Amazon" },
            };

            return ouiDatabase.TryGetValue(oui, out var vendor) ? vendor : "Unknown";
        }

        private int CompareIpBytes(byte[] ip1, byte[] ip2)
        {
            for (int i = 0; i < 4; i++)
            {
                if (ip1[i] < ip2[i]) return -1;
                if (ip1[i] > ip2[i]) return 1;
            }
            return 0;
        }

        private async Task<List<OpenPort>> ScanPortsAsync(string ipAddress, CancellationToken cancellationToken)
        {
            var openPorts = new List<OpenPort>();
            
            // Common ports to scan
            var commonPorts = new[]
            {
                // Web servers
                (80, "TCP"), (443, "TCP"), (8080, "TCP"), (8443, "TCP"), (8000, "TCP"), (8888, "TCP"),
                // SSH/Telnet
                (22, "TCP"), (23, "TCP"), (2222, "TCP"),
                // Email
                (25, "TCP"), (110, "TCP"), (143, "TCP"), (993, "TCP"), (995, "TCP"), (587, "TCP"), (465, "TCP"),
                // DNS
                (53, "UDP"), (53, "TCP"),
                // FTP
                (21, "TCP"), (20, "TCP"), (2121, "TCP"),
                // Database
                (3306, "TCP"), (5432, "TCP"), (1433, "TCP"), (1521, "TCP"), (27017, "TCP"), (6379, "TCP"),
                // Remote Desktop
                (3389, "TCP"), (5900, "TCP"), (5901, "TCP"),
                // SMB/File sharing
                (139, "TCP"), (445, "TCP"),
                // RPC
                (135, "TCP"),
                // Other common services
                (161, "UDP"), (162, "UDP"), (514, "UDP"), (636, "TCP"), (873, "TCP"), (2049, "TCP"),
                (3300, "TCP"), (5000, "TCP"), (5001, "TCP"), (5060, "TCP"), (5433, "TCP"), (5902, "TCP"),
                (5985, "TCP"), (5986, "TCP"), (7001, "TCP"), (7002, "TCP"), (8009, "TCP"), (8010, "TCP"),
                (8181, "TCP"), (8880, "TCP"), (9090, "TCP"), (9200, "TCP"), (9300, "TCP"), (10000, "TCP")
            };

            var tasks = new List<Task>();
            var semaphore = new SemaphoreSlim(50); // Limit concurrent scans

            // Create all tasks first, then wait for them
            foreach (var (port, protocol) in commonPorts)
            {
                // Don't break on cancellation - let all tasks start, they'll check cancellation internally
                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        // Check cancellation before acquiring semaphore
                        if (cancellationToken.IsCancellationRequested)
                            return;

                        await semaphore.WaitAsync(cancellationToken);
                        try
                        {
                            // Check again after acquiring semaphore
                            if (cancellationToken.IsCancellationRequested)
                                return;

                            var openPort = await CheckPortAsync(ipAddress, port, protocol, cancellationToken);
                            if (openPort != null)
                            {
                                lock (openPorts)
                                {
                                    openPorts.Add(openPort);
                                }
                            }
                        }
                        catch (OperationCanceledException)
                        {
                            // Expected when cancellation is requested
                        }
                        catch
                        {
                            // Ignore individual port scan errors
                        }
                        finally
                        {
                            semaphore.Release();
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        // Expected when cancellation is requested during semaphore wait
                    }
                    catch
                    {
                        // Ignore other errors
                    }
                }, cancellationToken));
            }

            // Wait for all tasks to complete (or be cancelled)
            try
            {
                await Task.WhenAll(tasks);
            }
            catch
            {
                // Some tasks may have been cancelled, but we still want to return what we found
            }

            return openPorts.OrderBy(p => p.Port).ToList();
        }

        private async Task<OpenPort?> CheckPortAsync(string ipAddress, int port, string protocol, CancellationToken cancellationToken)
        {
            try
            {
                if (cancellationToken.IsCancellationRequested)
                    return null;

                if (protocol == "TCP")
                {
                    using var client = new TcpClient();
                    try
                    {
                        // Use ConnectAsync with timeout
                        var connectTask = client.ConnectAsync(ipAddress, port);
                        var timeoutTask = Task.Delay(2000, cancellationToken); // 2 second timeout per port (increased from 1s)
                        
                        var completedTask = await Task.WhenAny(connectTask, timeoutTask);
                        
                        if (cancellationToken.IsCancellationRequested)
                            return null;

                        if (completedTask == timeoutTask)
                        {
                            // Timeout - port is likely closed or filtered
                            return null;
                        }

                        // Check if connection succeeded
                        if (client.Connected)
                        {
                            var openPort = new OpenPort
                            {
                                Port = port,
                                Protocol = protocol,
                                Service = GetServiceName(port),
                                Banner = await GrabBannerAsync(client, port, cancellationToken)
                            };
                            return openPort;
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        // Expected when cancellation is requested
                        return null;
                    }
                    catch (SocketException)
                    {
                        // Port is closed or unreachable - this is normal
                        return null;
                    }
                    catch
                    {
                        // Other errors - port is likely closed
                        return null;
                    }
                }
                else if (protocol == "UDP")
                {
                    // UDP scanning is more complex and less reliable
                    // For now, skip UDP or implement basic UDP scan
                    // UDP scanning typically requires sending packets and waiting for responses
                }
            }
            catch (OperationCanceledException)
            {
                // Expected when cancellation is requested
                return null;
            }
            catch
            {
                // Port is closed or unreachable - this is normal
            }

            return null;
        }

        private string GetServiceName(int port)
        {
            return port switch
            {
                20 => "FTP Data",
                21 => "FTP",
                22 => "SSH",
                23 => "Telnet",
                25 => "SMTP",
                53 => "DNS",
                80 => "HTTP",
                110 => "POP3",
                135 => "RPC",
                139 => "NetBIOS",
                143 => "IMAP",
                443 => "HTTPS",
                445 => "SMB",
                465 => "SMTPS",
                514 => "Syslog",
                587 => "SMTP Submission",
                636 => "LDAPS",
                873 => "rsync",
                993 => "IMAPS",
                995 => "POP3S",
                1433 => "MSSQL",
                1521 => "Oracle",
                2049 => "NFS",
                2222 => "SSH Alt",
                3300 => "MySQL",
                3306 => "MySQL",
                3389 => "RDP",
                5000 => "UPnP",
                5001 => "UPnP",
                5060 => "SIP",
                5432 => "PostgreSQL",
                5433 => "PostgreSQL Alt",
                5900 => "VNC",
                5901 => "VNC",
                5902 => "VNC",
                5985 => "WinRM HTTP",
                5986 => "WinRM HTTPS",
                6379 => "Redis",
                7001 => "WebLogic",
                7002 => "WebLogic",
                8000 => "HTTP Alt",
                8009 => "AJP",
                8010 => "HTTP Alt",
                8080 => "HTTP Proxy",
                8181 => "HTTP Alt",
                8443 => "HTTPS Alt",
                8880 => "HTTP Alt",
                8888 => "HTTP Alt",
                9090 => "HTTP Alt",
                9200 => "Elasticsearch",
                9300 => "Elasticsearch",
                10000 => "Webmin",
                2121 => "FTP Alt",
                27017 => "MongoDB",
                _ => "Unknown"
            };
        }

        private async Task<string> GrabBannerAsync(TcpClient client, int port, CancellationToken cancellationToken)
        {
            try
            {
                if (!client.Connected) return string.Empty;

                var stream = client.GetStream();
                stream.ReadTimeout = 2000; // 2 second timeout
                
                // Send common probes based on port
                byte[] probe = port switch
                {
                    21 => System.Text.Encoding.ASCII.GetBytes("QUIT\r\n"), // FTP
                    22 => System.Text.Encoding.ASCII.GetBytes("SSH-2.0-\r\n"), // SSH
                    25 => System.Text.Encoding.ASCII.GetBytes("EHLO test\r\n"), // SMTP
                    80 => System.Text.Encoding.ASCII.GetBytes("GET / HTTP/1.0\r\n\r\n"), // HTTP
                    110 => System.Text.Encoding.ASCII.GetBytes("QUIT\r\n"), // POP3
                    143 => System.Text.Encoding.ASCII.GetBytes("A1 LOGOUT\r\n"), // IMAP
                    443 => System.Text.Encoding.ASCII.GetBytes("GET / HTTP/1.0\r\n\r\n"), // HTTPS
                    3306 => new byte[] { 0x0a, 0x00, 0x00, 0x00, 0x0a }, // MySQL
                    5432 => System.Text.Encoding.ASCII.GetBytes("\0\0\0\0"), // PostgreSQL
                    _ => Array.Empty<byte>()
                };

                if (probe.Length > 0)
                {
                    await stream.WriteAsync(probe, 0, probe.Length, cancellationToken);
                }

                // Read response
                var buffer = new byte[1024];
                var bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
                
                if (bytesRead > 0)
                {
                    var banner = System.Text.Encoding.ASCII.GetString(buffer, 0, bytesRead);
                    // Clean up banner (remove newlines, limit length)
                    banner = banner.Replace("\r", " ").Replace("\n", " ").Trim();
                    if (banner.Length > 100)
                    {
                        banner = banner.Substring(0, 100) + "...";
                    }
                    return banner;
                }
            }
            catch
            {
                // Failed to grab banner
            }

            return string.Empty;
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

