using System;
using System.Linq;
using System.Threading.Tasks;
using System.Net;
using SharpPcap;
using SharpPcap.LibPcap;
using PacketDotNet;

namespace Dorothy.Models
{
    public abstract class FloodAttack : IDisposable
    {
        public event EventHandler<PacketEventArgs>? PacketSent;

        protected virtual void OnPacketSent(byte[] packet, IPAddress sourceIp, IPAddress destinationIp, int port)
        {
            PacketSent?.Invoke(this, new PacketEventArgs(packet, sourceIp, destinationIp, port));
        }

        protected LibPcapLiveDevice GetDevice()
        {
            // Get all devices that have an IP address
            var device = LibPcapLiveDeviceList.Instance
                .FirstOrDefault(d => d.Addresses != null && 
                    d.Addresses.Any(a => a.Addr?.ipAddress != null));

            if (device == null)
            {
                throw new InvalidOperationException("No suitable network interface found");
            }

            return device;
        }

        public abstract Task StartAsync();

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                // Cleanup resources
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }

    public class PacketEventArgs : EventArgs
    {
        public byte[] Packet { get; }
        public IPAddress SourceIp { get; }
        public IPAddress DestinationIp { get; }
        public int Port { get; }

        public PacketEventArgs(byte[] packet, IPAddress sourceIp, IPAddress destinationIp, int port)
        {
            Packet = packet;
            SourceIp = sourceIp;
            DestinationIp = destinationIp;
            Port = port;
        }
    }
} 