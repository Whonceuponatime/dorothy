using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
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

    public enum PortScanMode
    {
        None,           // No port scanning
        Common,         // Scan only most common ports (top 20)
        All,            // Scan all common ports (current behavior)
        Range,          // Scan a range of ports
        Selected        // Scan selected ports
    }

    public class NetworkScan
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();
        private readonly AttackLogger _attackLogger;
        private bool _intenseScan = false;
        private PortScanMode _portScanMode = PortScanMode.All;
        private int? _portRangeStart = null;
        private int? _portRangeEnd = null;
        private List<int> _selectedPorts = new List<int>();
        
        // Configurable timeouts (in milliseconds)
        private int _pingTimeout = 500;
        private int _tcpConnectTimeout = 1000;
        private int _dnsLookupTimeout = 2000;
        private int _bannerReadTimeout = 1000;
        
        // Concurrency settings
        private int _maxHostConcurrency = 32;
        
        // Optional features
        private bool _enableReverseDns = true;
        private bool _enableVendorLookup = true;
        private bool _enableBannerGrabbing = true;
        
        // Shared HttpClient for vendor lookups
        private static readonly HttpClient _sharedHttpClient = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(3)
        };

        public NetworkScan(AttackLogger attackLogger)
        {
            _attackLogger = attackLogger ?? throw new ArgumentNullException(nameof(attackLogger));
            
            // Initialize default values
            _pingTimeout = 500;
            _tcpConnectTimeout = 1000;
            _dnsLookupTimeout = 2000; // Shorter timeout for responsive scans
            _bannerReadTimeout = 1000;
            _maxHostConcurrency = 32;
            // Enable both DNS and vendor lookups during scan
            _enableReverseDns = true; // 2s timeout - resolves most local hostnames quickly
            _enableVendorLookup = true; // Uses local OUI database (instant, offline)
            _enableBannerGrabbing = true;
        }
        
        public void SetTimeouts(int pingTimeout = 500, int tcpConnectTimeout = 1000, int dnsLookupTimeout = 2000, int bannerReadTimeout = 1000)
        {
            _pingTimeout = pingTimeout;
            _tcpConnectTimeout = tcpConnectTimeout;
            _dnsLookupTimeout = dnsLookupTimeout;
            _bannerReadTimeout = bannerReadTimeout;
        }
        
        public void SetConcurrency(int maxHostConcurrency = 32)
        {
            _maxHostConcurrency = Math.Max(1, Math.Min(128, maxHostConcurrency));
        }
        
        public void SetOptionalFeatures(bool enableReverseDns = true, bool enableVendorLookup = true, bool enableBannerGrabbing = true)
        {
            _enableReverseDns = enableReverseDns;
            _enableVendorLookup = enableVendorLookup;
            _enableBannerGrabbing = enableBannerGrabbing;
        }

        public void SetScanMode(bool intenseScan)
        {
            _intenseScan = intenseScan;
        }

        public void SetPortScanMode(PortScanMode mode, int? rangeStart = null, int? rangeEnd = null, List<int>? selectedPorts = null)
        {
            _portScanMode = mode;
            _portRangeStart = rangeStart;
            _portRangeEnd = rangeEnd;
            _selectedPorts = selectedPorts ?? new List<int>();
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
            
            if (_attackLogger == null)
            {
                throw new InvalidOperationException("AttackLogger is not initialized");
            }
            
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
                    if (_attackLogger != null)
                    {
                        _attackLogger.LogInfo($"🔍 Starting custom range scan...");
                        _attackLogger.LogInfo($"Range: {startIp} - {endIp} ({totalHosts} hosts)");
                    }
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

                    if (_attackLogger != null)
                    {
                        _attackLogger.LogInfo($"🔍 Starting network scan...");
                        _attackLogger.LogInfo($"Network: {networkAddress}/{GetCidrNotation(maskBytes)}");
                        _attackLogger.LogInfo($"Scanning network range...");
                    }

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
                
                if (ipRange == null || ipRange.Count == 0)
                {
                    if (_attackLogger != null)
                        _attackLogger.LogWarning("No IPs to scan");
                    return assets;
                }
                
                int scanned = 0;
                var semaphore = new SemaphoreSlim(Math.Max(1, _maxHostConcurrency));
                var lockObject = new object();
                
                // Scan IP range with concurrency control
                var hostScanTasks = ipRange.Where(ip => !string.IsNullOrEmpty(ip)).Select(async ipString =>
                {
                    if (cancellationToken.IsCancellationRequested || string.IsNullOrEmpty(ipString))
                        return;
                    
                    try
                    {
                        await semaphore.WaitAsync(cancellationToken);
                    }
                    catch (OperationCanceledException)
                    {
                        return; // Scan was cancelled
                    }
                    catch
                    {
                        return; // Semaphore error
                    }
                    
                    try
                    {
                        NetworkAsset? foundAsset = null;
                        try
                        {
                            var asset = await ScanHostAsync(ipString, cancellationToken, _intenseScan);
                            if (asset != null)
                            {
                                lock (lockObject)
                                {
                                    assets.Add(asset);
                                    foundAsset = asset;
                                }
                                
                                // Log minimal info - detailed info is shown in the modal
                                var portInfo = _intenseScan && asset.OpenPorts != null && asset.OpenPorts.Count > 0 
                                    ? $" ({asset.OpenPorts.Count} open ports)" 
                                    : "";
                                if (_attackLogger != null)
                                    _attackLogger.LogInfo($"Found device: {asset.IpAddress}{portInfo}");
                            }
                        }
                        catch (Exception ex)
                        {
                            Logger.Debug(ex, $"Error scanning {ipString}");
                        }
                        finally
                        {
                            int currentScanned;
                            int foundCount;
                            lock (lockObject)
                            {
                                scanned++;
                                currentScanned = scanned;
                                foundCount = assets.Count;
                            }
                            
                            // Report progress with newly found asset (report every IP for real-time updates)
                            if (progress != null)
                            {
                                try
                                {
                                    var scanProgress = new ScanProgress
                                    {
                                        Scanned = currentScanned,
                                        Total = totalHosts,
                                        CurrentIp = ipString ?? string.Empty,
                                        Found = foundCount,
                                        NewAsset = foundAsset
                                    };
                                    progress.Report(scanProgress);
                                }
                                catch (Exception ex)
                                {
                                    // Ignore progress reporting errors
                                    Logger.Debug(ex, "Error reporting progress");
                                }
                            }
                            
                            if (currentScanned % 10 == 0 && _attackLogger != null)
                            {
                                _attackLogger.LogInfo($"Scanned {currentScanned}/{totalHosts} hosts...");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.Debug(ex, $"Error in scan task for {ipString}");
                    }
                    finally
                    {
                        try
                        {
                            semaphore.Release();
                        }
                        catch
                        {
                            // Ignore semaphore release errors
                        }
                    }
                });
                
                try
                {
                    await Task.WhenAll(hostScanTasks);
                }
                catch (Exception ex)
                {
                    Logger.Error(ex, "Error waiting for host scan tasks");
                }

                if (_attackLogger != null)
                    _attackLogger.LogSuccess($"✅ Network scan complete. Found {assets.Count} active devices.");
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Network scan failed");
                if (_attackLogger != null)
                    _attackLogger.LogError($"Network scan failed: {ex.Message}");
                throw;
            }

            return assets;
        }

        private async Task<NetworkAsset?> ScanHostAsync(string ipAddress, CancellationToken cancellationToken, bool intenseScan = false)
        {
            try
            {
                // Ping the host first with timeout
                using var ping = new Ping();
                PingReply? reply = null;
                try
                {
                    var pingTask = ping.SendPingAsync(ipAddress, _pingTimeout);
                    var pingTimeoutTask = Task.Delay(_pingTimeout, cancellationToken);
                    var pingCompleted = await Task.WhenAny(pingTask, pingTimeoutTask);
                    
                    if (pingCompleted == pingTimeoutTask || cancellationToken.IsCancellationRequested)
                    {
                        return null; // Timeout or cancelled
                    }
                    
                    reply = await pingTask;
                    if (reply == null || reply.Status != IPStatus.Success)
                    {
                        return null; // Host is not reachable
                    }
                }
                catch
                {
                    return null; // Ping failed
                }

                var asset = new NetworkAsset
                {
                    IpAddress = ipAddress,
                    IsReachable = true,
                    RoundTripTime = reply?.RoundtripTime ?? 0,
                    Status = "Online"
                };

                // Get MAC address (non-blocking, with timeout)
                try
                {
                    var macTask = GetMacAddressAsync(ipAddress);
                    var macTimeoutTask = Task.Delay(2000, cancellationToken);
                    var macCompleted = await Task.WhenAny(macTask, macTimeoutTask);
                    
                    if (macCompleted == macTask && !cancellationToken.IsCancellationRequested)
                    {
                        try
                        {
                            var macBytes = await macTask;
                            if (macBytes != null && macBytes.Length == 6)
                            {
                                asset.MacAddress = BitConverter.ToString(macBytes).Replace("-", ":");
                                
                                // Get vendor from local OUI database (fast, no timeout needed)
                                if (_enableVendorLookup)
                                {
                                    try
                                    {
                                        // Local OUI lookup is instant, no timeout needed
                                        asset.Vendor = await GetVendorFromMacAsync(asset.MacAddress);
                                    }
                                    catch
                                    {
                                        asset.Vendor = "Unknown";
                                    }
                                }
                                else
                                {
                                    asset.Vendor = "Unknown";
                                }
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

                // Get hostname (non-blocking, optional, with timeout)
                if (_enableReverseDns)
                {
                    try
                    {
                        var dnsTask = Dns.GetHostEntryAsync(ipAddress);
                        var dnsTimeoutTask = Task.Delay(_dnsLookupTimeout, cancellationToken);
                        var dnsCompleted = await Task.WhenAny(dnsTask, dnsTimeoutTask);
                        
                        if (dnsCompleted == dnsTask && !cancellationToken.IsCancellationRequested)
                        {
                            try
                            {
                                var hostEntry = await dnsTask;
                                if (hostEntry != null && !string.IsNullOrEmpty(hostEntry.HostName))
                                {
                                    asset.Hostname = hostEntry.HostName;
                                }
                                else
                                {
                                    asset.Hostname = "Unknown";
                                }
                            }
                            catch
                            {
                                asset.Hostname = "Unknown";
                            }
                        }
                        else
                        {
                            asset.Hostname = "Unknown";
                        }
                    }
                    catch
                    {
                        asset.Hostname = "Unknown";
                    }
                }
                else
                {
                    asset.Hostname = "Unknown";
                }

                // Intense scan: Port scanning and banner grabbing
                if (intenseScan && _portScanMode != PortScanMode.None)
                {
                    try
                    {
                        var openPorts = await ScanPortsAsync(ipAddress, cancellationToken);
                        asset.OpenPorts = openPorts ?? new List<OpenPort>();
                    }
                    catch (Exception ex)
                    {
                        Logger.Debug(ex, $"Error scanning ports for {ipAddress}");
                        asset.OpenPorts = new List<OpenPort>();
                    }
                }
                else
                {
                    asset.OpenPorts = new List<OpenPort>();
                }

                return asset;
            }
            catch (Exception ex)
            {
                Logger.Debug(ex, $"Error in ScanHostAsync for {ipAddress}");
                return null;
            }
        }

        // P/Invoke declarations for SendARP
        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern int SendARP(uint destIP, uint srcIP, byte[] macAddr, ref int macAddrLen);

        private async Task<byte[]> GetMacAddressAsync(string ipAddress)
        {
            try
            {
                // Try SendARP first (faster, no process spawning)
                var macBytes = GetMacAddressViaSendARP(ipAddress);
                if (macBytes != null && macBytes.Length == 6)
                {
                    return macBytes;
                }

                // If SendARP fails, try ARP table lookup
                var arpEntry = await GetArpEntryAsync(ipAddress);
                if (arpEntry != null)
                {
                    return ParseMacAddress(arpEntry);
                }

                // If not in ARP table, try ARP request via ping
                using var ping = new Ping();
                await ping.SendPingAsync(ipAddress, _pingTimeout);
                
                // Wait a bit for ARP to populate
                await Task.Delay(100);
                
                // Try SendARP again after ping
                macBytes = GetMacAddressViaSendARP(ipAddress);
                if (macBytes != null && macBytes.Length == 6)
                {
                    return macBytes;
                }
                
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

        private byte[]? GetMacAddressViaSendARP(string ipAddress)
        {
            try
            {
                if (!IPAddress.TryParse(ipAddress, out var ip))
                    return null;
                
                var ipBytes = ip.GetAddressBytes();
                if (ipBytes.Length != 4)
                    return null;
                
                uint destIP = BitConverter.ToUInt32(ipBytes, 0);
                uint srcIP = 0;
                byte[] macAddr = new byte[6];
                int macAddrLen = macAddr.Length;
                
                int result = SendARP(destIP, srcIP, macAddr, ref macAddrLen);
                
                if (result == 0 && macAddrLen == 6)
                {
                    // Check if MAC is not all zeros
                    if (macAddr.Any(b => b != 0))
                    {
                        return macAddr;
                    }
                }
            }
            catch
            {
                // SendARP failed, fall back to other methods
            }
            
            return null;
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

            // During scan, ONLY use local OUI database (fast, offline)
            // Online API lookups are done during sync instead
            return await Task.FromResult(GetVendorFromLocalDatabase(oui));
        }

        private string GetVendorFromLocalDatabase(string oui)
        {
            // Comprehensive OUI database with verified IEEE assignments
            var ouiDatabase = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                // Virtual/Hypervisors
                { "005056", "VMware" }, { "000C29", "VMware" }, { "000569", "VMware" },
                { "080027", "VirtualBox" }, { "0A0027", "VirtualBox" },
                { "00155D", "Hyper-V" }, { "001DD8", "Microsoft" },
                
                // Common network equipment and devices
                { "0010F3", "Nexans" }, // Network infrastructure
                { "F8A2CF", "Unknown" }, // Will be looked up online
                { "98E7F4", "Wistron Neweb" }, // Wireless/Network
                { "04D9F5", "Micro-Star" }, // MSI
                { "3C7C3F", "LG Electronics" },
                { "F8E43B", "Hon Hai Precision" }, // Foxconn
                { "305A3A", "AzureWave Technology" }, // Wireless modules
                { "50EBF6", "liteon" }, // Lite-On Technology
                { "58869C", "Samsung" },
                { "B0383B", "Hon Hai Precision" },
                { "C8B223", "D-Link" },
                { "E86A64", "Tp-Link" },
                
                // Apple - Verified OUIs
                { "A4C361", "Apple" }, { "BC9FEF", "Apple" }, { "64B9E8", "Apple" },
                { "DCBF54", "Apple" }, { "787B8A", "Apple" }, { "10DD01", "Apple" },
                { "F4F15A", "Apple" }, { "6C4D73", "Apple" }, { "9027E4", "Apple" },
                { "CCF9E8", "Apple" }, { "F02475", "Apple" }, { "ACBC32", "Apple" },
                { "3C2EF9", "Apple" }, { "AC7F3E", "Apple" }, { "F81EDF", "Apple" },
                { "04489A", "Apple" }, { "DC2B2A", "Apple" }, { "3451C9", "Apple" },
                
                // Samsung - Verified OUIs
                { "1CBDB9", "Samsung" }, { "E4121D", "Samsung" }, { "DC7144", "Samsung" },
                { "A81B5A", "Samsung" }, { "F4099B", "Samsung" }, { "48DB50", "Samsung" },
                { "BC8385", "Samsung" }, { "3C7A8A", "Samsung" }, { "086698", "Samsung" },
                { "30F769", "Samsung" }, { "001632", "Samsung" }, { "0000F0", "Samsung" },
                { "002399", "Samsung" }, { "002566", "Samsung" }, { "C89E43", "Samsung" },
                
                // Intel - Verified OUIs
                { "00AA00", "Intel" }, { "00AA01", "Intel" }, { "00AA02", "Intel" },
                { "00D0B7", "Intel" }, { "7085C2", "Intel" }, { "A4D1D2", "Intel" },
                { "DC53D4", "Intel" }, { "84A9C4", "Intel" }, { "48F17F", "Intel" },
                { "00C2C6", "Intel" }, { "001B21", "Intel" }, { "F0DEEF", "Intel" },
                { "941882", "Intel" }, { "685D43", "Intel" }, { "B4FCC4", "Intel" },
                
                // Realtek - Verified OUIs
                { "00E04C", "Realtek" }, { "525400", "Realtek" }, { "74DA38", "Realtek" },
                { "1C39BB", "Realtek" }, { "10C37B", "Realtek" },
                { "98DED0", "Realtek" }, { "801F02", "Realtek" }, { "30F9ED", "Realtek" },
                
                // Dell - Verified OUIs
                { "001C23", "Dell" }, { "002170", "Dell" }, { "00215D", "Dell" },
                { "001E4F", "Dell" }, { "78F7BE", "Dell" }, { "D4BED9", "Dell" },
                { "182033", "Dell" }, { "F04DA2", "Dell" }, { "609C9F", "Dell" },
                { "D89695", "Dell" }, { "241DD5", "Dell" },
                
                // HP - Verified OUIs
                { "001438", "HP" }, { "002324", "HP" },
                { "C08995", "HP" }, { "9C8E99", "HP" }, { "106FD0", "HP" },
                { "2C768A", "HP" }, { "6C3BE6", "HP" }, { "489A8A", "HP" },
                { "009C02", "HP" }, { "001E0B", "HP" },
                
                // Lenovo - Verified OUIs
                { "60F677", "Lenovo" }, { "5065F3", "Lenovo" }, { "1C69A5", "Lenovo" },
                { "74E543", "Lenovo" }, { "C82A14", "Lenovo" }, { "40F2E9", "Lenovo" },
                { "30C9AB", "Lenovo" }, { "9CBC36", "Lenovo" }, { "A01D48", "Lenovo" },
                
                // TP-Link - Verified OUIs
                { "F4EC38", "TP-Link" }, { "D82686", "TP-Link" }, { "C46E1F", "TP-Link" },
                { "A42BB0", "TP-Link" }, { "0CE150", "TP-Link" }, { "50D4F7", "TP-Link" },
                { "ECF196", "TP-Link" }, { "10FEED", "TP-Link" }, { "A04606", "TP-Link" },
                
                // ASUS - Verified OUIs
                { "2CF05D", "ASUS" }, { "1C87EC", "ASUS" },
                { "AC220B", "ASUS" }, { "04927A", "ASUS" }, { "7054D5", "ASUS" },
                { "38D547", "ASUS" }, { "F46D04", "ASUS" }, { "F832E4", "ASUS" },
                
                // Cisco - Verified OUIs
                { "00000C", "Cisco" }, { "00000D", "Cisco" }, { "00000E", "Cisco" },
                { "00000F", "Cisco" }, { "000102", "Cisco" }, { "0001C7", "Cisco" },
                { "0001C9", "Cisco" }, { "0001CB", "Cisco" }, { "68BDAB", "Cisco" },
                { "001D71", "Cisco" }, { "0021A0", "Cisco" },
                
                // Netgear - Verified OUIs
                { "0024B2", "Netgear" }, { "000FB5", "Netgear" }, { "001B2F", "Netgear" },
                { "001E2A", "Netgear" }, { "A021B7", "Netgear" }, { "4C9EFF", "Netgear" },
                { "E091F5", "Netgear" }, { "3490EA", "Netgear" }, { "0862660", "Netgear" },
                
                // D-Link - Verified OUIs
                { "000D88", "D-Link" }, { "001195", "D-Link" }, { "001346", "D-Link" },
                { "0015E9", "D-Link" }, { "001CF0", "D-Link" }, { "0022B0", "D-Link" },
                { "B8A386", "D-Link" }, { "1C7EE5", "D-Link" }, { "CCB255", "D-Link" },
                
                // Huawei - Verified OUIs
                { "00E00C", "Huawei" }, { "0018E7", "Huawei" }, { "00259E", "Huawei" },
                { "002692", "Huawei" }, { "C0A0BB", "Huawei" }, { "4C549F", "Huawei" },
                { "D4A9E8", "Huawei" }, { "30D1DC", "Huawei" }, { "786EB8", "Huawei" },
                
                // Xiaomi - Verified OUIs
                { "64B473", "Xiaomi" }, { "F8A45F", "Xiaomi" }, { "783A84", "Xiaomi" },
                { "50EC50", "Xiaomi" }, { "F0B429", "Xiaomi" }, { "34CE00", "Xiaomi" },
                { "D4619D", "Xiaomi" }, { "B0E235", "Xiaomi" }, { "5C63BF", "Xiaomi" },
                
                // Google/Nest - Verified OUIs
                { "54C0EB", "Google" }, { "54EAA8", "Google" }, { "3C5AB4", "Google" },
                { "94EB2C", "Google" }, { "C058EC", "Google" }, { "F4F5D8", "Google" },
                
                // Amazon/Ring - Verified OUIs
                { "74C246", "Amazon" }, { "ACF85C", "Amazon" }, { "84D6D0", "Amazon" },
                { "74C630", "Amazon" }, { "6854FD", "Amazon" }, { "0C47C9", "Amazon" },
                
                // Broadcom - Verified OUIs
                { "001018", "Broadcom" }, { "002618", "Broadcom" }, { "00D0C0", "Broadcom" },
                { "0090F8", "Broadcom" }, { "B49691", "Broadcom" }, { "E8B2AC", "Broadcom" },
                
                // Qualcomm - Verified OUIs
                { "009065", "Qualcomm" }, { "B0702D", "Qualcomm" }, { "C47C8D", "Qualcomm" },
                { "2C5491", "Qualcomm" }, { "8C15C7", "Qualcomm" }, { "001DA2", "Qualcomm" },
                
                // Sony - Verified OUIs
                { "001D0D", "Sony" }, { "002076", "Sony" }, { "00247E", "Sony" },
                { "7C669E", "Sony" }, { "18F46A", "Sony" }, { "F8321A", "Sony" },
                
                // LG - Verified OUIs
                { "001C62", "LG" }, { "001E75", "LG" }, { "B4B3CF", "LG" },
                { "9C97DC", "LG" }, { "789ED0", "LG" }, { "50685D", "LG" },
                
                // Motorola - Verified OUIs
                { "00139D", "Motorola" }, { "001ADB", "Motorola" }, { "9C5CF9", "Motorola" },
                { "0060A1", "Motorola" }, { "0004E2", "Motorola" },
                
                // Linksys/Belkin - Verified OUIs
                { "002129", "Linksys" }, { "00131A", "Linksys" }, { "001217", "Linksys" },
                { "000625", "Linksys" }, { "002275", "Linksys" },
                
                // Ubiquiti - Verified OUIs
                { "04185A", "Ubiquiti" }, { "18E829", "Ubiquiti" }, { "687251", "Ubiquiti" },
                { "24A43C", "Ubiquiti" }, { "FC0CAB", "Ubiquiti" },
                
                // Raspberry Pi Foundation
                { "B827EB", "Raspberry Pi" }, { "DCA632", "Raspberry Pi" }, { "E45F01", "Raspberry Pi" },
                
                // ASRock
                { "70856F", "ASRock" },
                
                // GIGABYTE
                { "1C697A", "GIGABYTE" }, { "9C6B00", "GIGABYTE" },
                
                // MSI
                { "00241D", "MSI" },
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
            
            if (string.IsNullOrEmpty(ipAddress))
                return openPorts;
            
            // Get ports to scan based on mode
            List<(int port, string protocol)> portsToScan = GetPortsToScan();
            
            if (portsToScan == null || portsToScan.Count == 0)
                return openPorts;

            // Use semaphore-limited concurrency pattern instead of creating thousands of tasks
            int maxConcurrent = Math.Min(100, portsToScan.Count);
            var semaphore = new SemaphoreSlim(maxConcurrent);
            var lockObject = new object();
            
            // Process ports in batches to avoid creating too many tasks at once
            var portScanTasks = portsToScan.Select(async portInfo =>
            {
                if (cancellationToken.IsCancellationRequested)
                    return;
                
                await semaphore.WaitAsync(cancellationToken);
                try
                {
                    if (cancellationToken.IsCancellationRequested)
                        return;
                    
                    var openPort = await CheckPortAsync(ipAddress, portInfo.port, portInfo.protocol, cancellationToken);
                    if (openPort != null)
                    {
                        lock (lockObject)
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
            });

            // Wait for all port scans to complete
            try
            {
                await Task.WhenAll(portScanTasks);
            }
            catch
            {
                // Some tasks may have been cancelled, but we still want to return what we found
            }

            return openPorts.OrderBy(p => p.Port).ToList();
        }

        private List<(int port, string protocol)> GetPortsToScan()
        {
            var ports = new List<(int port, string protocol)>();
            
            switch (_portScanMode)
            {
                case PortScanMode.None:
                    return ports;
                    
                case PortScanMode.Common:
                    // Top 20 most common ports (faster scanning)
                    ports.AddRange(new[]
                    {
                        (80, "TCP"), (443, "TCP"), (22, "TCP"), (21, "TCP"), (23, "TCP"),
                        (25, "TCP"), (53, "TCP"), (53, "UDP"), (110, "TCP"), (143, "TCP"),
                        (135, "TCP"), (139, "TCP"), (445, "TCP"), (993, "TCP"), (995, "TCP"),
                        (1723, "TCP"), (3306, "TCP"), (3389, "TCP"), (5432, "TCP"), (8080, "TCP")
                    });
                    break;
                    
                case PortScanMode.All:
                    // All common ports (current behavior)
                    ports.AddRange(new[]
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
                    });
                    break;
                    
                case PortScanMode.Range:
                    if (_portRangeStart.HasValue && _portRangeEnd.HasValue)
                    {
                        int start = Math.Max(1, Math.Min(_portRangeStart.Value, _portRangeEnd.Value));
                        int end = Math.Min(65535, Math.Max(_portRangeStart.Value, _portRangeEnd.Value));
                        
                        for (int port = start; port <= end; port++)
                        {
                            ports.Add((port, "TCP")); // Default to TCP for range scans
                        }
                    }
                    break;
                    
                case PortScanMode.Selected:
                    foreach (var port in _selectedPorts)
                    {
                        if (port >= 1 && port <= 65535)
                        {
                            ports.Add((port, "TCP")); // Default to TCP for selected ports
                        }
                    }
                    break;
            }
            
            return ports;
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
                        // Use ConnectAsync with configurable timeout
                        var connectTask = client.ConnectAsync(ipAddress, port);
                        var timeoutTask = Task.Delay(_tcpConnectTimeout, cancellationToken);
                        
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
                                Banner = _enableBannerGrabbing && ShouldGrabBanner(port) 
                                    ? await GrabBannerAsync(client, port, cancellationToken) 
                                    : string.Empty
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

        private bool ShouldGrabBanner(int port)
        {
            // Only grab banners for common ports to avoid delays
            return port switch
            {
                21 or 22 or 25 or 80 or 110 or 143 or 443 or 3306 or 5432 => true,
                _ => false
            };
        }

        private async Task<string> GrabBannerAsync(TcpClient client, int port, CancellationToken cancellationToken)
        {
            try
            {
                if (!client.Connected) return string.Empty;

                var stream = client.GetStream();
                stream.ReadTimeout = _bannerReadTimeout;
                
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

                // Read response with timeout
                var buffer = new byte[1024];
                var readTask = stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
                var readTimeoutTask = Task.Delay(_bannerReadTimeout, cancellationToken);
                var readCompleted = await Task.WhenAny(readTask, readTimeoutTask);
                
                if (readCompleted == readTimeoutTask || cancellationToken.IsCancellationRequested)
                {
                    return string.Empty; // Timeout or cancelled
                }
                
                var bytesRead = await readTask;
                
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

