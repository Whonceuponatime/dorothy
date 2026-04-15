using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using NLog;
using Dorothy.Network;

namespace Dorothy.Models
{
    public class ScanProgress
    {
        public int Scanned { get; set; }
        public int Total { get; set; }
        public string CurrentIp { get; set; } = string.Empty;
        public int Found { get; set; }
        public NetworkAsset? NewAsset { get; set; }
        public bool IsPortScanning { get; set; }
        public int PortsScanned { get; set; }
        public int TotalPorts { get; set; }
        public OpenPort? NewPort { get; set; }
        public string? PortScanIp { get; set; }
    }

    public class NetworkAsset
    {
        public string IpAddress { get; set; } = string.Empty;
        public string MacAddress { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Vendor { get; set; } = string.Empty;
        public bool IsReachable { get; set; }
        public long? RoundTripTime { get; set; }
        public string Status { get; set; } = string.Empty;
        public List<OpenPort> OpenPorts { get; set; } = new List<OpenPort>();
        public bool PortScanPerformed { get; set; } = false;

        public HashSet<string> OsHints { get; set; } = new HashSet<string>();
        public HashSet<string> ServiceHints { get; set; } = new HashSet<string>();

        public string OpenPortsDisplay => OpenPorts.Count > 0
            ? string.Join(", ", OpenPorts.Select(p =>
                string.IsNullOrEmpty(p.Banner)
                    ? $"{p.Port}/{p.Protocol}"
                    : $"{p.Port}/{p.Protocol} [{p.Banner}]"))
            : (PortScanPerformed ? "None" : "N/A");

        public string OsHintsDisplay => OsHints.Count > 0
            ? string.Join(", ", OsHints)
            : "Unknown";

        public string ServiceHintsDisplay => ServiceHints.Count > 0
            ? string.Join(", ", ServiceHints)
            : "Unknown";
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
        None,
        Common,
        All,
        Range,
        Selected
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

        private int _pingTimeout = 500;
        private int _tcpConnectTimeout = 1000;
        private int _dnsLookupTimeout = 2000;
        private int _bannerReadTimeout = 1000;

        private int _maxHostConcurrency = 32;

        private bool _enableReverseDns = true;
        private bool _enableVendorLookup = true;
        private bool _enableBannerGrabbing = true;
        private int _maxBannersPerHost = 20;

        public NetworkScan(AttackLogger attackLogger)
        {
            _attackLogger = attackLogger ?? throw new ArgumentNullException(nameof(attackLogger));

            _pingTimeout = 500;
            _tcpConnectTimeout = 1000;
            _dnsLookupTimeout = 2000;
            _bannerReadTimeout = 1000;
            _maxHostConcurrency = 32;

            _enableReverseDns = true;
            _enableVendorLookup = true;
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

            if (mode == PortScanMode.Selected)
            {
                _bannerReadTimeout = 3000;
            }
            else
            {
                _bannerReadTimeout = 1000;
            }
        }

        public async Task<List<NetworkAsset>> ScanNetworkBySubnetAsync(string networkAddress, string subnetMask, CancellationToken cancellationToken = default, IProgress<ScanProgress>? progress = null)
        {
            return await ScanNetworkAsync(networkAddress, subnetMask, null, null, cancellationToken, progress);
        }

        public async Task<List<NetworkAsset>> ScanNetworkByRangeAsync(string startIp, string endIp, CancellationToken cancellationToken = default, IProgress<ScanProgress>? progress = null)
        {
            return await ScanNetworkAsync(null, null, startIp, endIp, cancellationToken, progress);
        }

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

                    if (!IPAddress.TryParse(startIp, out var startIpObj) || !IPAddress.TryParse(endIp, out var endIpObj))
                    {
                        throw new ArgumentException($"Invalid IP range: {startIp} - {endIp}");
                    }

                    var startBytes = startIpObj.GetAddressBytes();
                    var endBytes = endIpObj.GetAddressBytes();

                    if (CompareIpBytes(startBytes, endBytes) > 0)
                    {
                        throw new ArgumentException($"Start IP ({startIp}) must be less than or equal to End IP ({endIp})");
                    }

                    var currentBytes = new byte[4];
                    Array.Copy(startBytes, currentBytes, 4);

                    while (CompareIpBytes(currentBytes, endBytes) <= 0)
                    {
                        ipRange.Add(string.Join(".", currentBytes));

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

                        if (CompareIpBytes(currentBytes, endBytes) > 0) break;
                    }

                    totalHosts = ipRange.Count;
                    if (_attackLogger != null)
                    {
                        _attackLogger.LogInfo($" Starting custom range scan...");
                        _attackLogger.LogInfo($"Range: {startIp} - {endIp} ({totalHosts} hosts)");
                    }
                }
                else if (!string.IsNullOrEmpty(networkAddress) && !string.IsNullOrEmpty(subnetMask))
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

                    var networkStart = new byte[4];
                    for (int i = 0; i < 4; i++)
                    {
                        networkStart[i] = (byte)(networkBytes[i] & maskBytes[i]);
                    }

                    if (_attackLogger != null)
                    {
                        _attackLogger.LogInfo($" Starting network scan...");
                        _attackLogger.LogInfo($"Network: {networkAddress}/{GetCidrNotation(maskBytes)}");
                        _attackLogger.LogInfo($"Scanning network range...");
                    }

                    totalHosts = CalculateHostCount(maskBytes);

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
                        return;
                    }
                    catch
                    {
                        return;
                    }

                    try
                    {
                        NetworkAsset? foundAsset = null;
                        try
                        {
                            var asset = await ScanHostAsync(ipString, cancellationToken, _intenseScan, progress);
                            if (asset != null)
                            {
                                lock (lockObject)
                                {
                                    assets.Add(asset);
                                    foundAsset = asset;
                                }

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

        private async Task<NetworkAsset?> ScanHostAsync(string ipAddress, CancellationToken cancellationToken, bool intenseScan = false, IProgress<ScanProgress>? progress = null)
        {
            try
            {

                using var ping = new Ping();
                PingReply? reply = null;
                try
                {
                    var pingTask = ping.SendPingAsync(ipAddress, _pingTimeout);
                    var pingTimeoutTask = Task.Delay(_pingTimeout, cancellationToken);
                    var pingCompleted = await Task.WhenAny(pingTask, pingTimeoutTask);

                    if (pingCompleted == pingTimeoutTask || cancellationToken.IsCancellationRequested)
                    {
                        return null;
                    }

                    reply = await pingTask;
                    if (reply == null || reply.Status != IPStatus.Success)
                    {
                        return null;
                    }
                }
                catch
                {
                    return null;
                }

                var asset = new NetworkAsset
                {
                    IpAddress = ipAddress,
                    IsReachable = true,
                    RoundTripTime = reply?.RoundtripTime ?? 0,
                    Status = "Online"
                };

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
                                _attackLogger.LogInfo($"MAC address retrieved: {asset.MacAddress} for IP: {ipAddress}");

                                    try
                                    {
                                    _attackLogger.LogInfo($" Looking up vendor for MAC: {asset.MacAddress}");

                                        asset.Vendor = await GetVendorFromMacAsync(asset.MacAddress);
                                    if (string.IsNullOrWhiteSpace(asset.Vendor) || asset.Vendor == "Unknown")
                                    {
                                        asset.Vendor = "Unknown";
                                    }
                                    _attackLogger.LogInfo($"Vendor resolved for {asset.MacAddress}: {asset.Vendor}");
                                }
                                catch (Exception ex)
                                {
                                    _attackLogger.LogWarning($"Failed to get vendor for MAC {asset.MacAddress}: {ex.Message}");
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
                        _attackLogger.LogWarning($" MAC address not retrieved for IP: {ipAddress} (timeout or failed)");
                        asset.MacAddress = "Unknown";
                        asset.Vendor = "Unknown";
                    }
                }
                catch (Exception ex)
                {
                    _attackLogger.LogWarning($" Exception getting MAC address for IP: {ipAddress}: {ex.Message}");
                    asset.MacAddress = "Unknown";
                    asset.Vendor = "Unknown";
                }

                if (_enableReverseDns)
                {
                    try
                    {
                        _attackLogger.LogInfo($" Looking up device name for IP: {ipAddress}");
                        asset.Name = await ResolveHostnameMultiMethodAsync(ipAddress, cancellationToken);
                        if (string.IsNullOrWhiteSpace(asset.Name) || asset.Name == "Unknown")
                        {
                            asset.Name = ipAddress;
                        }
                        _attackLogger.LogInfo($"Device name resolved for {ipAddress}: {asset.Name}");
                    }
                    catch (Exception ex)
                                {
                        _attackLogger.LogWarning($"Failed to resolve device name for {ipAddress}: {ex.Message}");
                        asset.Name = ipAddress;
                            }
                        }
                        else
                        {
                    _attackLogger.LogWarning($" Device name lookup disabled for {ipAddress}");
                    asset.Name = ipAddress;
                }

                if (intenseScan && (_portScanMode == PortScanMode.All || _portScanMode == PortScanMode.Range || _portScanMode == PortScanMode.Selected))
                {
                    try
                    {

                        IProgress<ScanProgress>? portProgress = progress != null ? new Progress<ScanProgress>(p =>
                        {
                            p.IsPortScanning = true;
                            p.PortScanIp = ipAddress;
                            progress.Report(p);
                        }) : null;

                        var openPorts = await ScanPortsAsync(ipAddress, cancellationToken, portProgress);
                        asset.OpenPorts = openPorts ?? new List<OpenPort>();
                        asset.PortScanPerformed = true;

                        foreach (var port in asset.OpenPorts)
                        {
                            if (!string.IsNullOrWhiteSpace(port.Banner))
                            {
                                UpdateOsAndServiceHints(asset, port.Banner, port.Port);
                            }
                        }

                        if (progress != null)
                        {
                            progress.Report(new ScanProgress
                            {
                                IsPortScanning = false,
                                PortScanIp = ipAddress
                            });
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.Debug(ex, $"Error scanning ports for {ipAddress}");
                        asset.OpenPorts = new List<OpenPort>();
                        asset.PortScanPerformed = true;

                        if (progress != null)
                        {
                            progress.Report(new ScanProgress
                            {
                                IsPortScanning = false,
                                PortScanIp = ipAddress
                            });
                        }
                    }
                }
                else
                {

                    asset.OpenPorts = new List<OpenPort>();
                    asset.PortScanPerformed = false;
                }

                return asset;
            }
            catch (Exception ex)
            {
                Logger.Debug(ex, $"Error in ScanHostAsync for {ipAddress}");
                return null;
            }
        }

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern int SendARP(uint destIP, uint srcIP, byte[] macAddr, ref int macAddrLen);

        private async Task<byte[]> GetMacAddressAsync(string ipAddress)
        {
            try
            {

                var macBytes = GetMacAddressViaSendARP(ipAddress);
                if (macBytes != null && macBytes.Length == 6)
                {
                    return macBytes;
                }

                var arpEntry = await GetArpEntryAsync(ipAddress);
                if (arpEntry != null)
                {
                    return ParseMacAddress(arpEntry);
                }

                using var ping = new Ping();
                await ping.SendPingAsync(ipAddress, _pingTimeout);

                await Task.Delay(100);

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

                    if (macAddr.Any(b => b != 0))
                    {
                        return macAddr;
                    }
                }
            }
            catch
            {

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

        private async Task<string> ResolveHostnameMultiMethodAsync(string ipAddress, CancellationToken cancellationToken)
        {

            bool isOnline = IsInternetAvailable();

            try
            {
                if (IPAddress.TryParse(ipAddress, out var ip))
                {
                    var dnsHostname = await HostnameResolver.ResolveHostnameAsync(ip, 1000);
                    if (!string.IsNullOrWhiteSpace(dnsHostname) && dnsHostname != ipAddress)
                    {
                        _attackLogger.LogInfo($"Hostname found via DNS/LLMNR: {dnsHostname}");
                        return dnsHostname;
                    }
                }
            }
            catch
            {

            }

            try
            {
                if (IPAddress.TryParse(ipAddress, out var ip))
        {
                    var netbiosHostname = await NetBiosNameQuery.QueryNetBiosNameAsync(ip, 800);
                    if (!string.IsNullOrWhiteSpace(netbiosHostname))
                    {
                        _attackLogger.LogInfo($"Hostname found via NetBIOS NBNS: {netbiosHostname}");
                        return netbiosHostname;
                    }
                }
            }
            catch
            {

            }

            try
            {
                var netbiosHostname = await GetNetBiosNameAsync(ipAddress, cancellationToken);
                if (!string.IsNullOrWhiteSpace(netbiosHostname) && netbiosHostname != "Unknown")
                {
                    _attackLogger.LogInfo($"Hostname found via nbtstat: {netbiosHostname}");
                    return netbiosHostname;
                }
            }
            catch
            {

            }

            try
            {
                var arpHostname = await GetHostnameFromArpTableAsync(ipAddress, cancellationToken);
                if (!string.IsNullOrWhiteSpace(arpHostname) && arpHostname != "Unknown")
            {
                    _attackLogger.LogInfo($"Hostname found via ARP table: {arpHostname}");
                    return arpHostname;
                }
            }
            catch
            {

            }

            if (isOnline)
            {

                return "Unknown";
            }

            _attackLogger.LogWarning($"Hostname not found for {ipAddress} (tried DNS/LLMNR, NetBIOS NBNS, nbtstat, ARP)");
            return "Unknown";
        }

        private bool IsInternetAvailable()
        {
            try
            {

                using var ping = new System.Net.NetworkInformation.Ping();
                var reply = ping.Send("8.8.8.8", 1000);
                return reply?.Status == System.Net.NetworkInformation.IPStatus.Success;
            }
            catch
            {

                return false;
            }
        }

        private async Task<string> GetNetBiosNameAsync(string ipAddress, CancellationToken cancellationToken)
        {
            try
            {

                using var process = new System.Diagnostics.Process
                {
                    StartInfo = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "nbtstat",
                        Arguments = $"-A {ipAddress}",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                var outputTask = process.StandardOutput.ReadToEndAsync();
                var timeoutTask = Task.Delay(2000, cancellationToken);
                var completed = await Task.WhenAny(outputTask, timeoutTask);

                if (completed == outputTask && !cancellationToken.IsCancellationRequested)
                {
                    var output = await outputTask;
                    await process.WaitForExitAsync();

                    var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                    string? bestName = null;

                    foreach (var line in lines)
                    {

                        if (line.Contains("Name") && line.Contains("Type") && line.Contains("Status"))
                            continue;
                        if (line.Contains("---") || line.Trim().Length == 0)
                            continue;

                        if (line.Contains("<00>") || line.Contains("<20>") || line.Contains("<03>"))
                        {

                            var parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                            if (parts.Length >= 1)
                            {
                                var name = parts[0].Trim();

                                name = name.TrimEnd();

                                if (!string.IsNullOrWhiteSpace(name) &&
                                    !name.Equals("Name", StringComparison.OrdinalIgnoreCase) &&
                                    !name.Equals("---", StringComparison.OrdinalIgnoreCase) &&
                                    !name.StartsWith("_", StringComparison.OrdinalIgnoreCase) &&
                                    name.Length <= 15)
                                {

                                    if (line.Contains("<00>") && bestName == null)
                                    {
                                        bestName = name;
                                    }

                                    else if (line.Contains("<20>") && bestName == null)
                                    {
                                        bestName = name;
                                    }

                                    else if (line.Contains("<03>") && bestName == null)
                                    {
                                        bestName = name;
                                    }
                                }
                            }
                        }
                    }

                    if (!string.IsNullOrWhiteSpace(bestName))
                    {

                        bestName = bestName.Trim();
                        while (bestName.Length > 0 && (bestName[bestName.Length - 1] == ' ' ||
                               bestName[bestName.Length - 1] < 32))
                        {
                            bestName = bestName.Substring(0, bestName.Length - 1);
                        }
                        if (!string.IsNullOrWhiteSpace(bestName) && bestName.Length <= 15)
                        {
                            return bestName;
                        }
                    }
                    else
                    {
                    }
                }
                else
                {
                    try { process.Kill(); } catch { }
                }
            }
            catch
            {

            }

            try
            {
                using var pingProcess = new System.Diagnostics.Process
                {
                    StartInfo = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "ping",
                        Arguments = $"-a -n 1 -w 2000 {ipAddress}",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    }
                };

                pingProcess.Start();
                var pingOutputTask = pingProcess.StandardOutput.ReadToEndAsync();
                var pingTimeoutTask = Task.Delay(3000, cancellationToken);
                var pingCompleted = await Task.WhenAny(pingOutputTask, pingTimeoutTask);

                if (pingCompleted == pingOutputTask && !cancellationToken.IsCancellationRequested)
                {
                    var pingOutput = await pingOutputTask;
                    await pingProcess.WaitForExitAsync();

                    var pingMatch = System.Text.RegularExpressions.Regex.Match(
                        pingOutput,
                        @"Pinging\s+([a-zA-Z0-9\-_\.]+)\s+\[",
                        System.Text.RegularExpressions.RegexOptions.IgnoreCase);

                    if (pingMatch.Success && pingMatch.Groups.Count > 1)
                    {
                        var hostname = pingMatch.Groups[1].Value.Trim();
                        if (!string.IsNullOrWhiteSpace(hostname) && hostname != ipAddress && !hostname.Contains("."))
                        {
                            _attackLogger.LogInfo($"Hostname found via ping -a: {hostname}");
                            return hostname;
                        }
                    }
                }
                else
                {
                    try { pingProcess.Kill(); } catch { }
                }
            }
            catch
            {

            }

            try
            {
                using var cacheProcess = new System.Diagnostics.Process
                {
                    StartInfo = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "nbtstat",
                        Arguments = "-n",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    }
                };

                cacheProcess.Start();
                var cacheOutputTask = cacheProcess.StandardOutput.ReadToEndAsync();
                var cacheTimeoutTask = Task.Delay(2000, cancellationToken);
                var cacheCompleted = await Task.WhenAny(cacheOutputTask, cacheTimeoutTask);

                if (cacheCompleted == cacheOutputTask && !cancellationToken.IsCancellationRequested)
                {
                    var cacheOutput = await cacheOutputTask;
                    await cacheProcess.WaitForExitAsync();

                    if (cacheOutput.Contains(ipAddress))
                    {
                        var lines = cacheOutput.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                        foreach (var line in lines)
                        {
                            if (line.Contains("<00>") && !line.Contains("Name") && !line.Contains("---"))
                            {
                                var parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                                if (parts.Length >= 1)
                                {
                                    var name = parts[0].Trim();
                                    if (!string.IsNullOrWhiteSpace(name) && name.Length <= 15)
                                    {
                                        _attackLogger.LogInfo($"Hostname found via nbtstat cache: {name}");
                                        return name;
                                    }
                                }
                            }
                        }
                    }
                }
                else
                {
                    try { cacheProcess.Kill(); } catch { }
                }
            }
            catch
            {

            }

            try
            {
                var dnsTask = System.Net.Dns.GetHostEntryAsync(ipAddress);
                var dnsTimeoutTask = Task.Delay(2000, cancellationToken);
                var dnsCompleted = await Task.WhenAny(dnsTask, dnsTimeoutTask);

                if (dnsCompleted == dnsTask && !cancellationToken.IsCancellationRequested)
                {
                    try
                    {
                        var hostEntry = await dnsTask;
                        if (hostEntry != null && !string.IsNullOrEmpty(hostEntry.HostName))
                        {
                            var hostname = hostEntry.HostName;

                            if (hostname.Contains("."))
                            {
                                hostname = hostname.Split('.')[0];
                            }
                            if (!string.IsNullOrWhiteSpace(hostname) && hostname != ipAddress)
                            {
                                _attackLogger.LogInfo($"Hostname found via DNS/LLMNR: {hostname}");
                                return hostname;
                            }
                        }
                    }
                    catch (System.Net.Sockets.SocketException)
                    {

                    }
                }
            }
            catch
            {

            }

            return "Unknown";
        }

        private async Task<string> GetHostnameFromArpTableAsync(string ipAddress, CancellationToken cancellationToken)
        {
            try
            {

                using var process = new System.Diagnostics.Process
                {
                    StartInfo = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = "arp",
                        Arguments = "-a",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                var outputTask = process.StandardOutput.ReadToEndAsync();
                var timeoutTask = Task.Delay(2000, cancellationToken);
                var completed = await Task.WhenAny(outputTask, timeoutTask);

                if (completed == outputTask && !cancellationToken.IsCancellationRequested)
                {
                    var output = await outputTask;
                    await process.WaitForExitAsync();

                    var patterns = new[]
                    {
                        $@"{System.Text.RegularExpressions.Regex.Escape(ipAddress)}\s+\(([^)]+)\)",
                        $@"{System.Text.RegularExpressions.Regex.Escape(ipAddress)}\s+([a-zA-Z0-9\-_\.]+)\s+[0-9a-fA-F]",
                    };

                    foreach (var pattern in patterns)
                    {
                        var match = System.Text.RegularExpressions.Regex.Match(
                            output,
                            pattern,
                            System.Text.RegularExpressions.RegexOptions.IgnoreCase);

                        if (match.Success && match.Groups.Count > 1)
                        {
                            var hostname = match.Groups[1].Value.Trim();
                            if (!string.IsNullOrWhiteSpace(hostname))
                            {
                                return hostname;
                            }
                        }
                    }
                }
                else
                {
                    try { process.Kill(); } catch { }
                }
            }
            catch
            {

            }

            return "Unknown";
        }

        private Task<string> GetVendorFromMacAsync(string macAddress)
        {
            if (string.IsNullOrWhiteSpace(macAddress) || macAddress == "Unknown")
            {
                return Task.FromResult("Unknown");
            }

            string cleanMac = macAddress.Replace(":", "").Replace("-", "").ToUpper();
            if (cleanMac.Length < 6)
            {
                return Task.FromResult("Unknown");
            }

            string oui = cleanMac.Substring(0, 6);

            var vendor = GetVendorFromLocalDatabase(oui);

            if (vendor != "Unknown")
            {
                _attackLogger.LogInfo($"Vendor found in offline database: {vendor} (OUI: {oui})");
            }
            else
            {
                _attackLogger.LogWarning($"Vendor lookup FAILED: OUI {oui} not found in local database");
            }

            return Task.FromResult(vendor);
        }

        private string GetVendorFromLocalDatabase(string oui)
        {

            var ouiDatabase = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {

                { "005056", "VMware" },
                { "000C29", "VMware" },
                { "000569", "VMware" },
                { "080027", "VirtualBox" },
                { "0A0027", "VirtualBox" },
                { "00155D", "Hyper-V" },
                { "001DD8", "Microsoft" },

                { "0010F3", "Nexans" },
                { "F8A2CF", "Unknown" },
                { "98E7F4", "Wistron Neweb" },
                { "04D9F5", "MSI" },
                { "3C7C3F", "LG Electronics" },
                { "F8E43B", "Hon Hai Precision" },
                { "305A3A", "AzureWave Technology" },
                { "50EBF6", "Lite-On Technology" },
                { "B0383B", "Hon Hai Precision" },
                { "C8B223", "D-Link" },
                { "E86A64", "TP-Link" },

                { "A4C361", "Apple" },
                { "BC9FEF", "Apple" },
                { "64B9E8", "Apple" },
                { "DCBF54", "Apple" },
                { "787B8A", "Apple" },
                { "10DD01", "Apple" },
                { "F4F15A", "Apple" },
                { "6C4D73", "Apple" },
                { "9027E4", "Apple" },
                { "CCF9E8", "Apple" },
                { "F02475", "Apple" },
                { "ACBC32", "Apple" },
                { "3C2EF9", "Apple" },
                { "AC7F3E", "Apple" },
                { "F81EDF", "Apple" },
                { "04489A", "Apple" },
                { "DC2B2A", "Apple" },
                { "3451C9", "Apple" },

                { "1CBDB9", "Samsung" },
                { "E4121D", "Samsung" },
                { "DC7144", "Samsung" },
                { "A81B5A", "Samsung" },
                { "F4099B", "Samsung" },
                { "48DB50", "Samsung" },
                { "BC8385", "Samsung" },
                { "3C7A8A", "Samsung" },
                { "086698", "Samsung" },
                { "30F769", "Samsung" },
                { "001632", "Samsung" },
                { "0000F0", "Samsung" },
                { "002399", "Samsung" },
                { "002566", "Samsung" },
                { "C89E43", "Samsung" },
                { "588694", "Samsung" },
                { "58869C", "Samsung" },
                { "B0386C", "Samsung" },
                { "30CDA7", "Samsung" },
                { "988389", "Samsung" },

                { "00AA00", "Intel" },
                { "00AA01", "Intel" },
                { "00AA02", "Intel" },
                { "00D0B7", "Intel" },
                { "7085C2", "Intel" },
                { "A4D1D2", "Intel" },
                { "DC53D4", "Intel" },
                { "84A9C4", "Intel" },
                { "48F17F", "Intel" },
                { "00C2C6", "Intel" },
                { "001B21", "Intel" },
                { "F0DEEF", "Intel" },
                { "941882", "Intel" },
                { "685D43", "Intel" },
                { "B4FCC4", "Intel" },

                { "00E04C", "Realtek" },
                { "525400", "Realtek" },
                { "74DA38", "Realtek" },
                { "1C39BB", "Realtek" },
                { "10C37B", "Realtek" },
                { "98DED0", "Realtek" },
                { "801F02", "Realtek" },
                { "30F9ED", "Realtek" },

                { "001C23", "Dell" },
                { "002170", "Dell" },
                { "00215D", "Dell" },
                { "001E4F", "Dell" },
                { "78F7BE", "Dell" },
                { "D4BED9", "Dell" },
                { "182033", "Dell" },
                { "F04DA2", "Dell" },
                { "609C9F", "Dell" },
                { "D89695", "Dell" },
                { "241DD5", "Dell" },
                { "4CD717", "Dell" },
                { "B07B25", "Dell" },

                { "001438", "HP" },
                { "002324", "HP" },
                { "C08995", "HP" },
                { "9C8E99", "HP" },
                { "106FD0", "HP" },
                { "2C768A", "HP" },
                { "6C3BE6", "HP" },
                { "489A8A", "HP" },
                { "009C02", "HP" },
                { "001E0B", "HP" },
                { "5C60BA", "HP" },
                { "E4E749", "HP" },

                { "60F677", "Lenovo" },
                { "5065F3", "Lenovo" },
                { "1C69A5", "Lenovo" },
                { "74E543", "Lenovo" },
                { "C82A14", "Lenovo" },
                { "40F2E9", "Lenovo" },
                { "30C9AB", "Lenovo" },
                { "9CBC36", "Lenovo" },
                { "A01D48", "Lenovo" },

                { "F4EC38", "TP-Link" },
                { "D82686", "TP-Link" },
                { "C46E1F", "TP-Link" },
                { "A42BB0", "TP-Link" },
                { "0CE150", "TP-Link" },
                { "50D4F7", "TP-Link" },
                { "ECF196", "TP-Link" },
                { "10FEED", "TP-Link" },
                { "A04606", "TP-Link" },
                { "1C3BF3", "TP-Link" },

                { "2CF05D", "ASUS" },
                { "1C87EC", "ASUS" },
                { "AC220B", "ASUS" },
                { "04927A", "ASUS" },
                { "7054D5", "ASUS" },
                { "38D547", "ASUS" },
                { "F46D04", "ASUS" },
                { "F832E4", "ASUS" },
                { "D45D64", "ASUS" },
                { "581122", "ASUS" },
                { "7C10C9", "ASUS" },
                { "6045CB", "ASUS" },
                { "BCFCE7", "ASUS" },
                { "FC3497", "ASUS" },
                { "74D02B", "ASUS" },
                { "B06EBF", "ASUS" },
                { "A85E45", "ASUS" },

                { "00000C", "Cisco" },
                { "00000D", "Cisco" },
                { "00000E", "Cisco" },
                { "00000F", "Cisco" },
                { "000102", "Cisco" },
                { "0001C7", "Cisco" },
                { "0001C9", "Cisco" },
                { "0001CB", "Cisco" },
                { "68BDAB", "Cisco" },
                { "001D71", "Cisco" },
                { "0021A0", "Cisco" },

                { "0024B2", "Netgear" },
                { "000FB5", "Netgear" },
                { "001B2F", "Netgear" },
                { "001E2A", "Netgear" },
                { "A021B7", "Netgear" },
                { "4C9EFF", "Netgear" },
                { "E091F5", "Netgear" },
                { "3490EA", "Netgear" },
                { "288088", "Netgear" },

                { "000D88", "D-Link" },
                { "001195", "D-Link" },
                { "001346", "D-Link" },
                { "0015E9", "D-Link" },
                { "001CF0", "D-Link" },
                { "0022B0", "D-Link" },
                { "B8A386", "D-Link" },
                { "1C7EE5", "D-Link" },
                { "CCB255", "D-Link" },

                { "00E00C", "Huawei" },
                { "0018E7", "Huawei" },
                { "00259E", "Huawei" },
                { "002692", "Huawei" },
                { "C0A0BB", "Huawei" },
                { "4C549F", "Huawei" },
                { "D4A9E8", "Huawei" },
                { "30D1DC", "Huawei" },
                { "786EB8", "Huawei" },

                { "64B473", "Xiaomi" },
                { "F8A45F", "Xiaomi" },
                { "783A84", "Xiaomi" },
                { "50EC50", "Xiaomi" },
                { "F0B429", "Xiaomi" },
                { "34CE00", "Xiaomi" },
                { "D4619D", "Xiaomi" },
                { "B0E235", "Xiaomi" },
                { "5C63BF", "Xiaomi" },

                { "54C0EB", "Google" },
                { "54EAA8", "Google" },
                { "3C5AB4", "Google" },
                { "94EB2C", "Google" },
                { "C058EC", "Google" },
                { "F4F5D8", "Google" },

                { "74C246", "Amazon" },
                { "ACF85C", "Amazon" },
                { "84D6D0", "Amazon" },
                { "74C630", "Amazon" },
                { "6854FD", "Amazon" },
                { "0C47C9", "Amazon" },

                { "001018", "Broadcom" },
                { "002618", "Broadcom" },
                { "00D0C0", "Broadcom" },
                { "0090F8", "Broadcom" },
                { "B49691", "Broadcom" },
                { "E8B2AC", "Broadcom" },

                { "009065", "Qualcomm" },
                { "B0702D", "Qualcomm" },
                { "C47C8D", "Qualcomm" },
                { "2C5491", "Qualcomm" },
                { "8C15C7", "Qualcomm" },
                { "001DA2", "Qualcomm" },

                { "001D0D", "Sony" },
                { "002076", "Sony" },
                { "00247E", "Sony" },
                { "7C669E", "Sony" },
                { "18F46A", "Sony" },
                { "F8321A", "Sony" },

                { "001C62", "LG" },
                { "001E75", "LG" },
                { "B4B3CF", "LG" },
                { "9C97DC", "LG" },
                { "789ED0", "LG" },
                { "50685D", "LG" },

                { "00139D", "Motorola" },
                { "001ADB", "Motorola" },
                { "9C5CF9", "Motorola" },
                { "0060A1", "Motorola" },
                { "0004E2", "Motorola" },

                { "002129", "Linksys" },
                { "00131A", "Linksys" },
                { "001217", "Linksys" },
                { "000625", "Linksys" },
                { "002275", "Linksys" },

                { "04185A", "Ubiquiti" },
                { "18E829", "Ubiquiti" },
                { "687251", "Ubiquiti" },
                { "24A43C", "Ubiquiti" },
                { "FC0CAB", "Ubiquiti" },

                { "B827EB", "Raspberry Pi" },
                { "DCA632", "Raspberry Pi" },
                { "E45F01", "Raspberry Pi" },

                { "70856F", "ASRock" },

                { "1C697A", "GIGABYTE" },
                { "9C6B00", "GIGABYTE" },

                { "00241D", "MSI" },
                { "448A5B", "MSI" },

                { "705DCC", "EFM Networks" },
                { "6C2408", "LCFC(Hefei) Electronics" },
                { "84BA3B", "Canon" },
                { "00E04D", "INTERNET INITIATIVE JAPAN" },
                { "3498B5", "S1 Corporation" },
                { "00089B", "S1 Corporation" },
                { "9009D0", "Synology" },
                { "D4CA6D", "MikroTik" },
                { "1853E0", "Hanyang Digitech" },

                { "0009E5", "Unknown" },
                { "A0CEC8", "Unknown" },
                { "245EBE", "Unknown" },
                { "000159", "Unknown" },
                { "107B44", "Unknown" },
                { "F8A26D", "Unknown" },
            };

            oui = oui.ToUpperInvariant();

            if (ouiDatabase.TryGetValue(oui, out var vendor))
            {
                _attackLogger.LogInfo($"Vendor lookup SUCCESS: OUI {oui} -> {vendor}");
                return vendor;
            }

            _attackLogger.LogWarning($"Vendor lookup FAILED: OUI {oui} not found in database (database has {ouiDatabase.Count} entries)");
            return "Unknown";
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

        private async Task<List<OpenPort>> ScanPortsAsync(string ipAddress, CancellationToken cancellationToken, IProgress<ScanProgress>? progress = null)
        {
            var openPorts = new List<OpenPort>();

            if (string.IsNullOrEmpty(ipAddress))
                return openPorts;

            List<(int port, string protocol)> portsToScan = GetPortsToScan();

            if (portsToScan == null || portsToScan.Count == 0)
                return openPorts;

            int originalTimeout = _tcpConnectTimeout;
            bool isLargeRangeScan = portsToScan.Count > 10000;
            if (isLargeRangeScan)
            {

                _tcpConnectTimeout = 300;
            }

            int totalPorts = portsToScan.Count;
            int scannedPorts = 0;
            int bannersGrabbed = 0;
            var lockObject = new object();
            DateTime lastProgressReport = DateTime.MinValue;
            const int minProgressIntervalMs = 100;

            int maxConcurrent;
            if (totalPorts > 10000)
            {

                maxConcurrent = Math.Min(500, totalPorts);
            }
            else if (totalPorts > 1000)
            {

                maxConcurrent = Math.Min(200, totalPorts);
            }
            else
            {

                maxConcurrent = Math.Min(100, totalPorts);
            }

            var semaphore = new SemaphoreSlim(maxConcurrent);

            int progressInterval = totalPorts > 10000 ? 50 : (totalPorts > 1000 ? 25 : 10);

            var portScanTasks = portsToScan.Select(async portInfo =>
            {
                if (cancellationToken.IsCancellationRequested)
                    return;

                await semaphore.WaitAsync(cancellationToken);
                try
                {
                    if (cancellationToken.IsCancellationRequested)
                        return;

                    bool skipBanner = bannersGrabbed >= _maxBannersPerHost;
                    var openPort = await CheckPortAsync(ipAddress, portInfo.port, portInfo.protocol, cancellationToken, skipBanner);

                    lock (lockObject)
                    {
                        scannedPorts++;
                        bool shouldReport = false;

                        if (openPort != null)
                        {
                            openPorts.Add(openPort);

                            if (!string.IsNullOrWhiteSpace(openPort.Banner))
                                bannersGrabbed++;

                            shouldReport = true;
                        }
                        else
                        {

                            var now = DateTime.UtcNow;
                            bool timeElapsed = (now - lastProgressReport).TotalMilliseconds >= minProgressIntervalMs;
                            bool intervalReached = scannedPorts % progressInterval == 0;

                            if (timeElapsed && intervalReached)
                            {
                                shouldReport = true;
                                lastProgressReport = now;
                            }
                        }

                        if (shouldReport && progress != null)
                        {
                            progress.Report(new ScanProgress
                            {
                                IsPortScanning = true,
                                PortScanIp = ipAddress,
                                PortsScanned = scannedPorts,
                                TotalPorts = totalPorts,
                                NewPort = openPort
                            });
                        }
                    }
                }
                catch (OperationCanceledException)
                {

                }
                catch
                {

                }
                finally
                {
                    semaphore.Release();
                }
            });

            try
            {
                await Task.WhenAll(portScanTasks);
            }
            catch
            {

            }
            finally
            {

                if (isLargeRangeScan)
                {
                    _tcpConnectTimeout = originalTimeout;
                }
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

                case PortScanMode.All:

                    ports.AddRange(new[]
                    {

                        (80, "TCP"), (443, "TCP"), (8080, "TCP"), (8443, "TCP"), (8000, "TCP"), (8888, "TCP"),

                        (22, "TCP"), (23, "TCP"), (2222, "TCP"),

                        (25, "TCP"), (110, "TCP"), (143, "TCP"), (993, "TCP"), (995, "TCP"), (587, "TCP"), (465, "TCP"),

                        (53, "UDP"), (53, "TCP"),

                        (21, "TCP"), (20, "TCP"), (2121, "TCP"),

                        (3306, "TCP"), (5432, "TCP"), (1433, "TCP"), (1521, "TCP"), (27017, "TCP"), (6379, "TCP"),

                        (3389, "TCP"), (5900, "TCP"), (5901, "TCP"),

                        (139, "TCP"), (445, "TCP"),

                        (135, "TCP"),

                        (161, "UDP"), (162, "UDP"), (514, "UDP"), (636, "TCP"), (873, "TCP"), (2049, "TCP"),
                        (3300, "TCP"), (5000, "TCP"), (5001, "TCP"), (5060, "TCP"), (5433, "TCP"), (5902, "TCP"),
                        (5985, "TCP"), (5986, "TCP"), (7001, "TCP"), (7002, "TCP"), (8009, "TCP"), (8010, "TCP"),
                        (8181, "TCP"), (8880, "TCP"), (9090, "TCP"), (9200, "TCP"), (9300, "TCP"), (10000, "TCP")
                    });
                    break;

                case PortScanMode.Range:

                    int start = _portRangeStart.HasValue ? Math.Max(1, Math.Min(_portRangeStart.Value, _portRangeEnd ?? 65535)) : 1;
                    int end = _portRangeEnd.HasValue ? Math.Min(65535, Math.Max(_portRangeStart ?? 1, _portRangeEnd.Value)) : 65535;

                        for (int port = start; port <= end; port++)
                        {
                            ports.Add((port, "TCP"));
                    }
                    break;

                case PortScanMode.Selected:
                    foreach (var port in _selectedPorts)
                    {
                        if (port >= 1 && port <= 65535)
                        {
                            ports.Add((port, "TCP"));
                        }
                    }
                    break;
            }

            return ports;
        }

        private async Task<OpenPort?> CheckPortAsync(string ipAddress, int port, string protocol, CancellationToken cancellationToken, bool skipBanner = false)
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

                        var connectTask = client.ConnectAsync(ipAddress, port);
                        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                        timeoutCts.CancelAfter(_tcpConnectTimeout);

                        try
                        {
                            await connectTask.WaitAsync(timeoutCts.Token);
                        }
                        catch (OperationCanceledException) when (timeoutCts.Token.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
                        {

                            return null;
                        }

                        if (cancellationToken.IsCancellationRequested)
                            return null;

                        if (client.Connected)
                        {
                            string rawBanner = string.Empty;
                            if (!skipBanner && _enableBannerGrabbing && ShouldGrabBanner(port))
                            {
                                rawBanner = await GrabBannerAsync(client, port, cancellationToken);
                            }

                            var openPort = new OpenPort
                            {
                                Port = port,
                                Protocol = protocol,
                                Service = GetServiceName(port),
                                Banner = FingerprintBanner(port, rawBanner)
                            };
                            return openPort;
                        }
                    }
                    catch (OperationCanceledException)
                    {

                        return null;
                    }
                    catch (SocketException)
                    {

                        return null;
                    }
                    catch
                    {

                        return null;
                    }
                }
                else if (protocol == "UDP")
                {

                }
            }
            catch (OperationCanceledException)
            {

                return null;
            }
            catch
            {

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

        private string FingerprintBanner(int port, string banner)
        {
            if (string.IsNullOrWhiteSpace(banner))
                return banner;

            string lower = banner.ToLowerInvariant();

            if (port is 80 or 8080 or 443)
            {

                string status = null;
                string server = null;

                foreach (var line in banner.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    if (status == null && line.StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase))
                        status = line.Trim();

                    if (server == null && line.StartsWith("Server:", StringComparison.OrdinalIgnoreCase))
                        server = line.Trim();
                }

                if (status != null || server != null)
                    return $"{status ?? "HTTP"} | {server ?? "Server header not exposed"}";
            }

            if (port == 22 && lower.StartsWith("ssh-"))
            {

                return $"SSH banner: {banner}";
            }

            if (port is 25 or 110 or 143 || banner.StartsWith("220 ", StringComparison.OrdinalIgnoreCase) || banner.StartsWith("* OK", StringComparison.OrdinalIgnoreCase))
            {
                return $"Mail service banner: {banner}";
            }

            if (port == 3306 && banner.Contains("mysql", StringComparison.OrdinalIgnoreCase))
            {
                return $"MySQL banner: {banner}";
            }

            var known = new (string needle, string label)[]
            {
                ("openssh", "OpenSSH server"),
                ("dropbear", "Dropbear SSH"),
                ("nginx/", "nginx HTTP server"),
                ("apache/", "Apache HTTP server"),
                ("iis", "Microsoft IIS"),
                ("postfix", "Postfix SMTP"),
                ("exim", "Exim SMTP"),
                ("dovecot", "Dovecot IMAP/POP3"),
                ("vsftpd", "vsftpd FTP server"),
                ("proftpd", "ProFTPD FTP server"),
                ("pure-ftpd", "Pure-FTPd FTP server")
            };

            foreach (var (needle, label) in known)
            {
                if (lower.Contains(needle))
                    return $"{label}: {banner}";
            }

            return banner;
        }

        private void UpdateOsAndServiceHints(NetworkAsset asset, string banner, int port)
        {
            if (string.IsNullOrWhiteSpace(banner))
                return;

            string lower = banner.ToLowerInvariant();

            if (lower.Contains("ubuntu") || lower.Contains("debian") || lower.Contains("centos") ||
                lower.Contains("rhel") || lower.Contains("red hat") || lower.Contains("fedora") ||
                lower.Contains("suse") || lower.Contains("arch linux"))
            {
                asset.OsHints.Add("Linux");
            }
            else if (lower.Contains("microsoft-iis") || lower.Contains("windows") ||
                     lower.Contains("win32") || lower.Contains("server") && lower.Contains("microsoft"))
            {
                asset.OsHints.Add("Windows");
            }
            else if (lower.Contains("freebsd") || lower.Contains("openbsd") || lower.Contains("netbsd"))
            {
                asset.OsHints.Add("BSD");
            }

            if (port is 80 or 8080 or 443 || lower.Contains("http") || lower.Contains("nginx") ||
                lower.Contains("apache") || lower.Contains("iis"))
            {
                asset.ServiceHints.Add("HTTP(S)");
            }

            if (port == 22 || lower.Contains("ssh") || lower.Contains("openssh") || lower.Contains("dropbear"))
            {
                asset.ServiceHints.Add("SSH");
            }

            if (port is 25 or 587 || lower.Contains("smtp") || lower.Contains("postfix") || lower.Contains("exim"))
            {
                asset.ServiceHints.Add("SMTP");
            }

            if (port is 110 or 995 || lower.Contains("pop3") || lower.Contains("dovecot"))
            {
                asset.ServiceHints.Add("POP3");
            }

            if (port is 143 or 993 || lower.Contains("imap") || lower.Contains("dovecot"))
            {
                asset.ServiceHints.Add("IMAP");
            }

            if (port == 21 || lower.Contains("ftp") || lower.Contains("vsftpd") ||
                lower.Contains("proftpd") || lower.Contains("pure-ftpd"))
            {
                asset.ServiceHints.Add("FTP");
            }

            if (port == 3306 || lower.Contains("mysql"))
            {
                asset.ServiceHints.Add("MySQL");
            }

            if (port == 5432 || lower.Contains("postgresql") || lower.Contains("postgres"))
            {
                asset.ServiceHints.Add("PostgreSQL");
            }

            if (port is 135 or 139 or 445 || lower.Contains("smb") || lower.Contains("netbios"))
            {
                asset.ServiceHints.Add("SMB/NetBIOS");
            }

            if (port == 3389 || lower.Contains("rdp"))
            {
                asset.ServiceHints.Add("RDP");
            }
        }

        private bool ShouldGrabBanner(int port)
        {
            if (!_enableBannerGrabbing)
                return false;

            if (_portScanMode == PortScanMode.Selected)
                return true;

            return false;
        }

        private int GetTimeoutForPort(int port, bool isSelectedMode)
        {

            int baseTimeout = isSelectedMode ? 3000 : _bannerReadTimeout;

            return port switch
            {

                80 or 8080 or 22 or 21 => Math.Min(baseTimeout, 1000),

                25 or 110 or 143 or 587 or 993 or 995 => Math.Max(baseTimeout, 2000),

                3306 or 5432 => Math.Min(baseTimeout, 1500),

                443 or 993 or 995 => Math.Max(baseTimeout, 2000),

                _ => baseTimeout
            };
        }

        private async Task<string> GrabBannerAsync(TcpClient client, int port, CancellationToken cancellationToken)
        {
            if (!client.Connected)
                return GetNoBannerHint(port);

            int bannerTimeout = GetTimeoutForPort(port, _portScanMode == PortScanMode.Selected);

            try
            {
                var stream = client.GetStream();
                stream.ReadTimeout = bannerTimeout;

                bool serverSpeaksFirst = port is 21 or 22 or 25 or 110 or 143 or 3306 or 5432;
                bool tlsPort = port is 443 or 993 or 995;

                var buffer = new byte[1024];

                if (tlsPort)
                {
                    string tlsInfo = await TryTlsFingerprintAsync(stream, port, bannerTimeout, cancellationToken);
                    if (!string.IsNullOrEmpty(tlsInfo))
                        return tlsInfo;

                    int tlsBytes = await ReadWithTimeoutAsync(stream, buffer, 0, buffer.Length, bannerTimeout, cancellationToken);
                    if (tlsBytes > 0)
                        return NormalizeBanner(buffer, tlsBytes, forceHex: true, port);

                    return GetNoBannerHint(port);
                }

                if (serverSpeaksFirst)
                {
                    int initialBytes = await ReadWithTimeoutAsync(stream, buffer, 0, buffer.Length, bannerTimeout, cancellationToken);
                    if (initialBytes > 0)
                        return NormalizeBanner(buffer, initialBytes, forceHex: false, port);

                    await Task.Delay(100, cancellationToken);
                    initialBytes = await ReadWithTimeoutAsync(stream, buffer, 0, buffer.Length, bannerTimeout, cancellationToken);
                    if (initialBytes > 0)
                        return NormalizeBanner(buffer, initialBytes, forceHex: false, port);
                }

                byte[] probe = GetProbeForPort(port);

                if (probe.Length > 0)
                {
                    await stream.WriteAsync(probe, 0, probe.Length, cancellationToken);
                }
                else
                {

                    await Task.Delay(100, cancellationToken);
                }

                int bytesRead = await ReadWithTimeoutAsync(stream, buffer, 0, buffer.Length, bannerTimeout, cancellationToken);
                if (bytesRead > 0)
                    return NormalizeBanner(buffer, bytesRead, forceHex: false, port);
            }
            catch
            {

            }

            return GetNoBannerHint(port);
        }

        private static async Task<string> TryTlsFingerprintAsync(
            NetworkStream baseStream,
            int port,
            int timeoutMs,
            CancellationToken cancellationToken)
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(timeoutMs);

            using var ssl = new SslStream(
                baseStream,
                leaveInnerStreamOpen: true,
                (sender, cert, chain, errors) => true);

            try
            {
                var options = new SslClientAuthenticationOptions
                {
                    TargetHost = "localhost",
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck
                };

                await ssl.AuthenticateAsClientAsync(options, cts.Token);

                var cert = ssl.RemoteCertificate as X509Certificate2;
                if (cert == null && ssl.RemoteCertificate != null)
                    cert = new X509Certificate2(ssl.RemoteCertificate);

                string protocol = ssl.SslProtocol.ToString();

                if (cert != null)
                {
                    string subject = cert.GetNameInfo(X509NameType.SimpleName, false);
                    string issuer = cert.GetNameInfo(X509NameType.SimpleName, true);
                    string expires = cert.NotAfter.ToString("yyyy-MM-dd");

                    return $"TLS {protocol} CN={subject}, Issuer={issuer}, Expires={expires}";
                }

                return $"TLS {protocol} (no certificate details)";
            }
            catch
            {

                return string.Empty;
            }
        }

        private static async Task<int> ReadWithTimeoutAsync(
            NetworkStream stream,
            byte[] buffer,
            int offset,
            int maxBytes,
            int timeoutMs,
            CancellationToken cancellationToken)
        {
            int total = 0;

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(timeoutMs);

            try
            {
                while (total < maxBytes && !cts.IsCancellationRequested)
                {
                    if (!stream.DataAvailable)
                    {
                        await Task.Delay(20, cts.Token);
                        continue;
                    }

                    int read = await stream.ReadAsync(buffer, offset + total, maxBytes - total, cts.Token);
                    if (read <= 0)
                        break;

                    total += read;
                }
            }
            catch
            {

            }

            return total;
        }

        private static byte[] GetProbeForPort(int port)
        {
            return port switch
            {
                21  => Encoding.ASCII.GetBytes("QUIT\r\n"),
                22  => Encoding.ASCII.GetBytes("SSH-2.0-SEACURE-SCAN\r\n"),
                23  => Encoding.ASCII.GetBytes("\r\n"),
                25  => Encoding.ASCII.GetBytes("EHLO seacure.local\r\n"),
                53  => new byte[] { 0x00, 0x00, 0x01, 0x00 },
                80  => Encoding.ASCII.GetBytes("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"),
                110 => Encoding.ASCII.GetBytes("QUIT\r\n"),
                135 => new byte[] { 0x00, 0x00, 0x00, 0x00 },
                139 => new byte[] { 0x00, 0x00, 0x00 },
                143 => Encoding.ASCII.GetBytes("A1 LOGOUT\r\n"),

                445 => new byte[] { 0x00, 0x00, 0x00 },
                3389 => new byte[]
                {
                    0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00
                },
                3306 => new byte[] { 0x0a, 0x00, 0x00, 0x00, 0x0a },
                5432 => new byte[] { 0x00, 0x00, 0x00, 0x00 },
                8080 => Encoding.ASCII.GetBytes("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"),
                _   => Array.Empty<byte>()
            };
        }

        private static string NormalizeBanner(byte[] buffer, int length, bool forceHex, int port)
        {
            if (length <= 0)
                return string.Empty;

            if (!forceHex)
            {
                try
                {
                    string s = Encoding.ASCII.GetString(buffer, 0, length);

                    int controlCount = 0;
                    foreach (char c in s)
                    {
                        if (c < 0x20 && c != '\r' && c != '\n' && c != '\t')
                            controlCount++;
                    }

                    if (controlCount <= s.Length / 4)
                    {
                        s = s.Replace("\r", " ").Replace("\n", " ").Trim();
                        if (s.Length > 100)
                            s = s[..100] + "...";
                        return s;
                    }
                }
                catch
                {

                }
            }

            string hex = BitConverter.ToString(buffer, 0, length).Replace("-", " ");
            string hint = GetBinaryProtocolHint(port, buffer, length);

            return string.IsNullOrEmpty(hint) ? hex : $"{hint} | {hex}";
        }

        private static string GetBinaryProtocolHint(int port, byte[] buffer, int length)
        {
            if (length < 4)
                return string.Empty;

            if ((port == 445 || port == 139) && length >= 4)
            {

                if (buffer[0] == 0xFF && buffer[1] == 0x53 && buffer[2] == 0x4D && buffer[3] == 0x42)
                    return "SMBv1 service detected (binary, legacy/vulnerable family)";

                if (buffer[0] == 0xFE && buffer[1] == 0x53 && buffer[2] == 0x4D && buffer[3] == 0x42)
                    return "SMBv2/3 service detected (binary)";

                return "SMB / NetBIOS service detected (binary)";
            }

            if (port == 3389 && length >= 2)
            {
                if (buffer[0] == 0x03 && buffer[1] == 0x00)
                {

                    if (length >= 4)
                    {
                        int tpktLength = (buffer[2] << 8) | buffer[3];
                        if (tpktLength > 0 && tpktLength <= 8192)
                            return "RDP service detected (X.224/TLS negotiation, confirmed)";
                    }
                    return "RDP service detected (X.224/TLS negotiation)";
                }
            }

            if (port == 135 && length >= 2)
            {
                if (buffer[0] == 0x05 && buffer[1] == 0x00)
                    return "MS RPC endpoint mapper detected (binary, DCE/RPC)";
            }

            if ((port == 443 || port == 993 || port == 995) && length >= 3)
            {
                if (buffer[0] == 0x16 && buffer[1] == 0x03)
                    return "TLS service detected (binary handshake)";
            }

            return string.Empty;
        }

        private static string GetNoBannerHint(int port)
        {
            return port switch
            {
                135 => "Open likely MS RPC endpoint mapper (no banner, requires DCE/RPC negotiation)",
                139 => "Open likely NetBIOS/SMB over NetBIOS (no banner, requires SMB session)",
                445 => "Open likely SMB over TCP (no banner, requires SMB negotiation)",
                3389 => "Open likely RDP (no banner, requires full RDP handshake)",
                443 => "Open likely HTTPS/TLS (no plain banner, TLS handshake required)",
                993 => "Open likely IMAPS (no plain banner, TLS handshake required)",
                995 => "Open likely POP3S (no plain banner, TLS handshake required)",
                _   => string.Empty
            };
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

