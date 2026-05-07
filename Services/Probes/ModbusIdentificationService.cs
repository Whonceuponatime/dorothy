using System;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Dorothy.Models;

namespace Dorothy.Services.Probes
{
    /// <summary>
    /// Modbus presence check — TCP connect-and-close to port 502. Round 1
    /// scope is presence detection only; protocol-specific identification
    /// (FC 43 / MEI 14 Read Device Identification) is intentionally out
    /// of scope. The deep parser was removed when the user re-scoped
    /// Round 1 to "identify the host has Modbus open" rather than
    /// "interrogate the device for vendor/firmware".
    /// </summary>
    public class ModbusIdentificationService
    {
        private const int ModbusPort        = 502;
        private const int ConnectTimeoutMs  = 750;

        public async Task<ModbusInfo?> IdentifyAsync(string ipAddress, CancellationToken ct)
        {
            try
            {
                using var tcp = new TcpClient();
                using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                connectCts.CancelAfter(ConnectTimeoutMs);
                await tcp.ConnectAsync(ipAddress, ModbusPort, connectCts.Token).ConfigureAwait(false);
                return new ModbusInfo
                {
                    PortOpen = true,
                    ProbedAt = DateTime.UtcNow
                };
            }
            catch
            {
                return null;
            }
        }
    }
}
