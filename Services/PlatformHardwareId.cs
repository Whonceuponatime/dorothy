using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
#if WINDOWS
using System.Management;
#endif
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using NLog;

namespace Dorothy.Services
{
    /// <summary>
    /// Cross-platform hardware ID generation service.
    /// Uses WMI on Windows and /proc/sys on Linux.
    /// </summary>
    public static class PlatformHardwareId
    {
        private static readonly ILogger Logger = LogManager.GetCurrentClassLogger();

        public static string GenerateHardwareId()
        {
            var components = new List<string>();

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                components.AddRange(GetWindowsHardwareComponents());
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                components.AddRange(GetLinuxHardwareComponents());
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                components.AddRange(GetMacOSHardwareComponents());
            }

            // If we couldn't get any components, use a fallback
            if (components.Count == 0)
            {
                components.Add(Environment.MachineName);
                components.Add(Environment.UserName);
            }

            // Create a hash of all components
            var combined = string.Join("|", components);
            using (var sha256 = SHA256.Create())
            {
                var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(combined));
                var hashString = BitConverter.ToString(hashBytes).Replace("-", "").ToUpper();
                
                // Return first 32 characters as hardware ID
                return hashString.Substring(0, Math.Min(32, hashString.Length));
            }
        }

        private static List<string> GetWindowsHardwareComponents()
        {
            var components = new List<string>();

#if WINDOWS
            try
            {
                // CPU Processor ID (static, unique per CPU)
                using (var searcher = new ManagementObjectSearcher("SELECT ProcessorId FROM Win32_Processor"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        var processorId = obj["ProcessorId"]?.ToString();
                        if (!string.IsNullOrWhiteSpace(processorId) && processorId != "To Be Filled By O.E.M.")
                        {
                            components.Add($"CPU:{processorId}");
                            break; // Use first valid CPU
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Debug(ex, "Could not retrieve CPU Processor ID");
            }

            try
            {
                // Motherboard Serial Number (static, unique per motherboard)
                using (var searcher = new ManagementObjectSearcher("SELECT SerialNumber FROM Win32_BaseBoard"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        var serialNumber = obj["SerialNumber"]?.ToString();
                        if (!string.IsNullOrWhiteSpace(serialNumber) && serialNumber != "To Be Filled By O.E.M.")
                        {
                            components.Add($"MB:{serialNumber}");
                            break;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Debug(ex, "Could not retrieve motherboard serial number");
            }

            try
            {
                // Get all physical disk drives
                using (var searcher = new ManagementObjectSearcher("SELECT SerialNumber, MediaType, InterfaceType FROM Win32_DiskDrive WHERE MediaType='Fixed hard disk media' OR InterfaceType='IDE' OR InterfaceType='SATA' OR InterfaceType='SCSI' OR InterfaceType='NVMe'"))
                {
                    var diskSerials = new List<string>();
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        var serialNumber = obj["SerialNumber"]?.ToString();
                        if (!string.IsNullOrWhiteSpace(serialNumber) && 
                            serialNumber.Trim() != "" &&
                            !serialNumber.Contains("0000") &&
                            serialNumber.Length > 5)
                        {
                            diskSerials.Add(serialNumber.Trim());
                        }
                    }
                    
                    foreach (var serial in diskSerials.OrderBy(s => s))
                    {
                        components.Add($"HDD:{serial}");
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Debug(ex, "Could not retrieve hard drive serial numbers");
            }

            try
            {
                // BIOS Serial Number
                using (var searcher = new ManagementObjectSearcher("SELECT SerialNumber FROM Win32_BIOS"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        var biosSerial = obj["SerialNumber"]?.ToString();
                        if (!string.IsNullOrWhiteSpace(biosSerial) && 
                            biosSerial != "To Be Filled By O.E.M." &&
                            biosSerial.Trim().Length > 3)
                        {
                            components.Add($"BIOS:{biosSerial.Trim()}");
                            break;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Debug(ex, "Could not retrieve BIOS serial number");
            }
#endif

            return components;
        }

        private static List<string> GetLinuxHardwareComponents()
        {
            var components = new List<string>();

            try
            {
                // Machine ID (unique per Linux installation)
                var machineIdPath = "/etc/machine-id";
                if (File.Exists(machineIdPath))
                {
                    var machineId = File.ReadAllText(machineIdPath).Trim();
                    if (!string.IsNullOrWhiteSpace(machineId))
                    {
                        components.Add($"MACHINE_ID:{machineId}");
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Debug(ex, "Could not read /etc/machine-id");
            }

            try
            {
                // CPU Serial/Model (from /proc/cpuinfo)
                if (File.Exists("/proc/cpuinfo"))
                {
                    var cpuInfo = File.ReadAllText("/proc/cpuinfo");
                    var lines = cpuInfo.Split('\n');
                    var processorIds = new HashSet<string>();
                    
                    foreach (var line in lines)
                    {
                        if (line.StartsWith("Serial") || line.StartsWith("processor"))
                        {
                            var parts = line.Split(':');
                            if (parts.Length > 1)
                            {
                                var value = parts[1].Trim();
                                if (!string.IsNullOrWhiteSpace(value) && value.Length > 3)
                                {
                                    processorIds.Add(value);
                                }
                            }
                        }
                    }
                    
                    foreach (var id in processorIds)
                    {
                        components.Add($"CPU:{id}");
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Debug(ex, "Could not read /proc/cpuinfo");
            }

            try
            {
                // DMI/SMBIOS information (if available)
                var dmiPaths = new[]
                {
                    "/sys/class/dmi/id/product_uuid",
                    "/sys/class/dmi/id/product_serial",
                    "/sys/class/dmi/id/board_serial"
                };

                foreach (var path in dmiPaths)
                {
                    if (File.Exists(path))
                    {
                        try
                        {
                            var value = File.ReadAllText(path).Trim();
                            if (!string.IsNullOrWhiteSpace(value) && value != "Not Specified" && value.Length > 3)
                            {
                                var key = Path.GetFileName(path).ToUpper();
                                components.Add($"{key}:{value}");
                            }
                        }
                        catch { }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Debug(ex, "Could not read DMI information");
            }

            try
            {
                // Disk serial numbers (using lsblk or /dev/disk/by-id)
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "lsblk",
                        Arguments = "-o SERIAL -n",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                if (process.ExitCode == 0 && !string.IsNullOrWhiteSpace(output))
                {
                    var serials = output.Split('\n')
                        .Where(s => !string.IsNullOrWhiteSpace(s) && s.Trim().Length > 3)
                        .Select(s => s.Trim())
                        .Distinct();

                    foreach (var serial in serials)
                    {
                        components.Add($"DISK:{serial}");
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Debug(ex, "Could not retrieve disk serial numbers via lsblk");
            }

            return components;
        }

        private static List<string> GetMacOSHardwareComponents()
        {
            var components = new List<string>();

            try
            {
                // System UUID
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "system_profiler",
                        Arguments = "SPHardwareDataType",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                if (process.ExitCode == 0)
                {
                    var lines = output.Split('\n');
                    foreach (var line in lines)
                    {
                        if (line.Contains("Hardware UUID"))
                        {
                            var parts = line.Split(':');
                            if (parts.Length > 1)
                            {
                                var uuid = parts[1].Trim();
                                if (!string.IsNullOrWhiteSpace(uuid))
                                {
                                    components.Add($"UUID:{uuid}");
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.Debug(ex, "Could not retrieve macOS hardware UUID");
            }

            return components;
        }
    }
}

