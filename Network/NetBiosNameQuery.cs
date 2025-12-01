using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace Dorothy.Network
{
    public static class NetBiosNameQuery
    {
        /// <summary>
        /// Queries NetBIOS Name Service (UDP 137) for a Windows-style hostname (e.g. DESKTOP-ABC).
        /// Returns null if no response or not a Windows host.
        /// </summary>
        public static async Task<string?> QueryNetBiosNameAsync(IPAddress ip, int timeoutMs = 800)
        {
            var request = BuildQueryPacket();

            using var udp = new UdpClient();
            udp.Client.ReceiveTimeout = timeoutMs;
            udp.Connect(ip, 137);

            try
            {
                await udp.SendAsync(request, request.Length);

                var receiveTask = udp.ReceiveAsync();
                var completed = await Task.WhenAny(receiveTask, Task.Delay(timeoutMs));
                if (completed != receiveTask)
                    return null;

                var response = receiveTask.Result.Buffer;
                return ParseNetBiosName(response);
            }
            catch
            {
                return null;
            }
            finally
            {
                udp?.Close();
            }
        }

        // Minimal NBNS Name Query packet for wildcard "*"
        private static byte[] BuildQueryPacket()
        {
            var packet = new byte[50];
            var rand = new Random();
            var id = (ushort)rand.Next(ushort.MinValue, ushort.MaxValue);

            // Transaction ID
            packet[0] = (byte)(id >> 8);
            packet[1] = (byte)(id & 0xFF);

            // Flags: 0x0010 = standard query
            packet[2] = 0x00;
            packet[3] = 0x10;

            // Questions: 0x0001
            packet[4] = 0x00;
            packet[5] = 0x01;

            // Answer RRs, Authority RRs, Additional RRs = 0
            // (bytes 6..11 already zero)

            // Name: encoded "*" (wildcard) per RFC 1002
            // At offset 12
            packet[12] = 0x20; // length
            var starName = EncodeNetBiosName("*");
            Buffer.BlockCopy(starName, 0, packet, 13, starName.Length);

            // Terminating 0
            packet[46] = 0x00;

            // Type NB (0x0020)
            packet[47] = 0x00;
            packet[48] = 0x20;

            // Class IN (0x0001)
            packet[49] = 0x01;

            return packet;
        }

        private static byte[] EncodeNetBiosName(string name)
        {
            // NetBIOS name: 16 bytes, pad with spaces
            var padded = (name ?? string.Empty).PadRight(15).Substring(0, 15) + "\0";
            var ascii = padded.ToUpperInvariant().ToCharArray();

            var result = new byte[32];

            for (int i = 0; i < 16; i++)
            {
                int c = ascii[i];
                int high = (c >> 4) & 0x0F;
                int low = c & 0x0F;
                result[2 * i] = (byte)('A' + high);
                result[2 * i + 1] = (byte)('A' + low);
            }

            return result;
        }

        private static string? ParseNetBiosName(byte[] buffer)
        {
            if (buffer.Length < 57) // minimal NBNS response size
                return null;

            // Name table starts after header + question. For a quick-and-dirty approach,
            // we look for the first 15-char NetBIOS name in the NAME section.

            // Scan for the first 0x20 byte which is usually the length byte of the encoded name in the answer.
            int idx = Array.IndexOf(buffer, (byte)0x20, 12);
            if (idx < 0 || idx + 1 >= buffer.Length)
                return null;

            // Next byte should be the first of encoded 32-byte name, but responses format varies.
            // For simplicity, some implementations just parse the Name Table entries starting at fixed offset.
            // Here we hack a very simple extraction by looking near the end of the packet:
            //
            // In practice: the "real" called name is 15 bytes ASCII + suffix type.
            // It usually appears near the end of the packet; we can locate the sequence where the 16th byte is the suffix.
            // To keep this short, we fallback to searching for the first 15 printable ASCII chars region.

            for (int i = 0; i < buffer.Length - 16; i++)
            {
                // require 15 printable chars and one suffix
                bool printable = true;
                for (int j = 0; j < 15; j++)
                {
                    byte b = buffer[i + j];
                    if (b < 0x20 || b > 0x5A) // rough filter
                    {
                        printable = false;
                        break;
                    }
                }

                if (!printable)
                    continue;

                var nameBytes = buffer.Skip(i).Take(15).ToArray();
                var name = System.Text.Encoding.ASCII.GetString(nameBytes).TrimEnd();

                // Very simple sanity check: Windows names often start with a letter
                if (!string.IsNullOrWhiteSpace(name))
                    return name;
            }

            return null;
        }
    }
}



