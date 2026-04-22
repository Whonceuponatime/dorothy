using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Dorothy.Models;

namespace Dorothy.Services
{
    public static class TargetIpExpander
    {
        public static List<string> Expand(string input, int cap = 1024)
        {
            var result = new List<string>();
            if (string.IsNullOrWhiteSpace(input)) return result;

            var parts = input.Split(new[] { ',', ';', ' ', '\n', '\r', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (var raw in parts)
            {
                var token = raw.Trim();
                if (token.Length == 0) continue;
                if (result.Count >= cap) break;

                if (token.Contains('/'))
                {
                    ExpandCidr(token, result, cap);
                }
                else if (token.Contains('-'))
                {
                    ExpandRange(token, result, cap);
                }
                else if (IPAddress.TryParse(token, out var ip))
                {
                    AddUnique(result, ip.ToString(), cap);
                }
            }

            return result;
        }

        private static void ExpandCidr(string token, List<string> result, int cap)
        {
            var slash = token.IndexOf('/');
            if (slash <= 0) return;
            var baseAddr = token.Substring(0, slash);
            if (!IPAddress.TryParse(baseAddr, out var ip)) return;
            if (ip.AddressFamily != AddressFamily.InterNetwork) return;
            if (!int.TryParse(token.Substring(slash + 1), out var prefix)) return;
            if (prefix < 0 || prefix > 32) return;

            var bytes = ip.GetAddressBytes();
            uint addr = ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
            uint mask = prefix == 0 ? 0u : 0xFFFFFFFFu << (32 - prefix);
            uint network = addr & mask;
            uint broadcast = network | ~mask;

            uint start = network;
            uint end = broadcast;
            if (prefix < 31)
            {
                start = network + 1;
                end = broadcast - 1;
            }

            for (uint v = start; v <= end && v >= start; v++)
            {
                if (result.Count >= cap) break;
                var s = $"{(v >> 24) & 0xFF}.{(v >> 16) & 0xFF}.{(v >> 8) & 0xFF}.{v & 0xFF}";
                AddUnique(result, s, cap);
                if (v == uint.MaxValue) break;
            }
        }

        private static void ExpandRange(string token, List<string> result, int cap)
        {
            var dash = token.IndexOf('-');
            var left = token.Substring(0, dash).Trim();
            var right = token.Substring(dash + 1).Trim();
            if (!IPAddress.TryParse(left, out var leftIp)) return;
            if (leftIp.AddressFamily != AddressFamily.InterNetwork) return;

            var leftBytes = leftIp.GetAddressBytes();
            uint leftAddr = ((uint)leftBytes[0] << 24) | ((uint)leftBytes[1] << 16) | ((uint)leftBytes[2] << 8) | leftBytes[3];
            uint rightAddr;

            if (IPAddress.TryParse(right, out var rightIp) && rightIp.AddressFamily == AddressFamily.InterNetwork)
            {
                var rb = rightIp.GetAddressBytes();
                rightAddr = ((uint)rb[0] << 24) | ((uint)rb[1] << 16) | ((uint)rb[2] << 8) | rb[3];
            }
            else if (byte.TryParse(right, out var lastOctet))
            {
                rightAddr = (leftAddr & 0xFFFFFF00u) | lastOctet;
            }
            else
            {
                return;
            }

            if (rightAddr < leftAddr) (leftAddr, rightAddr) = (rightAddr, leftAddr);

            for (uint v = leftAddr; v <= rightAddr && v >= leftAddr; v++)
            {
                if (result.Count >= cap) break;
                var s = $"{(v >> 24) & 0xFF}.{(v >> 16) & 0xFF}.{(v >> 8) & 0xFF}.{v & 0xFF}";
                AddUnique(result, s, cap);
                if (v == uint.MaxValue) break;
            }
        }

        private static void AddUnique(List<string> result, string ip, int cap)
        {
            if (result.Count >= cap) return;
            if (!result.Contains(ip)) result.Add(ip);
        }

        public static (RouteStatus status, string? gateway) DetermineRoute(string targetIp, string sourceIp)
        {
            if (!IPAddress.TryParse(targetIp, out var target)) return (RouteStatus.Unknown, null);
            if (!IPAddress.TryParse(sourceIp, out var source)) return (RouteStatus.Unknown, null);
            if (target.AddressFamily != AddressFamily.InterNetwork) return (RouteStatus.Unknown, null);

            var targetBytes = target.GetAddressBytes();
            uint targetAddr = ((uint)targetBytes[0] << 24) | ((uint)targetBytes[1] << 16) | ((uint)targetBytes[2] << 8) | targetBytes[3];

            string? defaultGateway = null;

            try
            {
                foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus != OperationalStatus.Up) continue;
                    var props = nic.GetIPProperties();
                    bool matchedNic = false;
                    foreach (var addr in props.UnicastAddresses)
                    {
                        if (addr.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                        if (addr.Address.Equals(source)) matchedNic = true;

                        var nicBytes = addr.Address.GetAddressBytes();
                        uint nicAddr = ((uint)nicBytes[0] << 24) | ((uint)nicBytes[1] << 16) | ((uint)nicBytes[2] << 8) | nicBytes[3];

                        int prefix = addr.PrefixLength;
                        if (prefix <= 0 || prefix > 32)
                        {
                            var maskBytes = addr.IPv4Mask?.GetAddressBytes();
                            if (maskBytes == null || maskBytes.Length != 4) continue;
                            uint maskVal = ((uint)maskBytes[0] << 24) | ((uint)maskBytes[1] << 16) | ((uint)maskBytes[2] << 8) | maskBytes[3];
                            if ((nicAddr & maskVal) == (targetAddr & maskVal))
                            {
                                return (RouteStatus.Local, null);
                            }
                        }
                        else
                        {
                            uint mask = prefix == 0 ? 0u : 0xFFFFFFFFu << (32 - prefix);
                            if ((nicAddr & mask) == (targetAddr & mask))
                            {
                                return (RouteStatus.Local, null);
                            }
                        }
                    }

                    if (matchedNic || defaultGateway == null)
                    {
                        foreach (var gw in props.GatewayAddresses)
                        {
                            if (gw.Address == null) continue;
                            if (gw.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                            var gwStr = gw.Address.ToString();
                            if (gwStr == "0.0.0.0") continue;
                            defaultGateway = gwStr;
                            if (matchedNic) break;
                        }
                    }
                }
            }
            catch
            {
                return (RouteStatus.Unknown, null);
            }

            if (!string.IsNullOrEmpty(defaultGateway))
            {
                return (RouteStatus.ViaGateway, defaultGateway);
            }

            return (RouteStatus.NoRoute, null);
        }
    }
}
