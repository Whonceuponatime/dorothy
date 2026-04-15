using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace Dorothy.Network
{
    public static class NetBiosNameQuery
    {

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

        private static byte[] BuildQueryPacket()
        {
            var packet = new byte[50];
            var rand = new Random();
            var id = (ushort)rand.Next(ushort.MinValue, ushort.MaxValue);

            packet[0] = (byte)(id >> 8);
            packet[1] = (byte)(id & 0xFF);

            packet[2] = 0x00;
            packet[3] = 0x10;

            packet[4] = 0x00;
            packet[5] = 0x01;

            packet[12] = 0x20;
            var starName = EncodeNetBiosName("*");
            Buffer.BlockCopy(starName, 0, packet, 13, starName.Length);

            packet[46] = 0x00;

            packet[47] = 0x00;
            packet[48] = 0x20;

            packet[49] = 0x01;

            return packet;
        }

        private static byte[] EncodeNetBiosName(string name)
        {

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
            if (buffer.Length < 57)
                return null;

            int idx = Array.IndexOf(buffer, (byte)0x20, 12);
            if (idx < 0 || idx + 1 >= buffer.Length)
                return null;

            for (int i = 0; i < buffer.Length - 16; i++)
            {

                bool printable = true;
                for (int j = 0; j < 15; j++)
                {
                    byte b = buffer[i + j];
                    if (b < 0x20 || b > 0x5A)
                    {
                        printable = false;
                        break;
                    }
                }

                if (!printable)
                    continue;

                var nameBytes = buffer.Skip(i).Take(15).ToArray();
                var name = System.Text.Encoding.ASCII.GetString(nameBytes).TrimEnd();

                if (!string.IsNullOrWhiteSpace(name))
                    return name;
            }

            return null;
        }
    }
}

