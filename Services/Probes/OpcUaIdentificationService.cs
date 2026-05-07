using System;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Dorothy.Models;

namespace Dorothy.Services.Probes
{
    /// <summary>
    /// OPC UA presence check — TCP connect-and-close to port 4840. Round 1
    /// scope is presence detection only; the OPC UA Hello/OPN/GetEndpoints
    /// binary handshake and SecurityPolicyUri analysis are intentionally
    /// out of scope. The full protocol parser was removed when the user
    /// re-scoped Round 1 to "identify the host has OPC UA open" rather
    /// than "interrogate the server's endpoint catalog".
    /// </summary>
    public class OpcUaIdentificationService
    {
        private const int OpcUaPort         = 4840;
        private const int ConnectTimeoutMs  = 750;

        public async Task<OpcUaInfo?> IdentifyAsync(string ipAddress, CancellationToken ct)
        {
            try
            {
                using var tcp = new TcpClient();
                using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                connectCts.CancelAfter(ConnectTimeoutMs);
                await tcp.ConnectAsync(ipAddress, OpcUaPort, connectCts.Token).ConfigureAwait(false);
                return new OpcUaInfo
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
