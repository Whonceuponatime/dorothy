using System;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Diagnostics;
using System.Windows.Forms;
using Dorothy;
using System.Windows.Forms.DataVisualization.Charting;
using System.Net;
using System.IO;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Threading.Tasks;

namespace Dorothy
{
    public partial class Form1 : Form
    {
        private AttackLogic _attackLogic = new AttackLogic();

        public Form1()
        {
            InitializeComponent();
            
            // Initialize the chart
            chartNetworkLoad.ChartAreas.Add(new ChartArea("Default"));
            Series series = new Series("Network Load");
            series.ChartType = SeriesChartType.Line;
            chartNetworkLoad.Series.Add(series);
        }

        private void btnAutoLoad_Click(object sender, EventArgs e)
        {
            // Auto-load the local machine's IP and MAC address
            txtTargetIP.Text = GetLocalIPAddress();
            txtMACAddress.Text = GetLocalMACAddress();
        }

        private void btnPing_Click(object sender, EventArgs e)
        {
            string targetIp = txtTargetIP.Text;
            bool pingSuccess = PingHost(targetIp);
            if (pingSuccess)
            {
                btnPing.BackgroundImage = new Bitmap(btnPing.Width, btnPing.Height);
                using (Graphics g = Graphics.FromImage(btnPing.BackgroundImage))
                {
                    g.FillRectangle(CreateGradientBrush(Color.LightGreen, Color.Green, 45f), 0, 0, btnPing.Width, btnPing.Height);
                }
                LogWithTimestamp($"Ping to {targetIp} was successful. Target is alive.", Color.LightBlue);
            }
            else
            {
                btnPing.BackgroundImage = null;
                btnPing.BackColor = SystemColors.Control;
                LogWithTimestamp($"Ping to {targetIp} failed. Target may be unreachable.", Color.LightCoral);
            }
        }

        private bool PingHost(string ipAddress)
        {
            try
            {
                using (Ping ping = new Ping())
                {
                    PingReply reply = ping.Send(ipAddress, 1000);
                    if (reply.Status == IPStatus.Success)
                    {
                        string ttl = reply.Options?.Ttl.ToString() ?? "N/A";
                        LogWithTimestamp($"Ping to {ipAddress} successful. Round-trip time: {reply.RoundtripTime}ms, TTL: {ttl}", Color.Pink);
                        return true;
                    }
                    else
                    {
                        LogWithTimestamp($"Ping to {ipAddress} failed. Status: {reply.Status}", Color.Pink);
                        return false;
                    }
                }
            }
            catch (PingException ex)
            {
                LogWithTimestamp($"Ping error: {ex.Message}", Color.Pink);
                return false;
            }
            catch (Exception ex)
            {
                LogWithTimestamp($"Unexpected error during ping: {ex.Message}", Color.Pink);
                return false;
            }
        }

        private void btnGetMAC_Click(object sender, EventArgs e)
        {
            string targetIp = txtTargetIP.Text;
            string macAddress = GetMACAddress(targetIp);
            txtMACAddress.Text = macAddress;
            LogWithTimestamp($"MAC Address for {targetIp}: {macAddress}", Color.LightBlue);
        }

        private string GetMACAddress(string ipAddress)
        {
            try
            {
                using (var process = new Process())
                {
                    process.StartInfo.FileName = "arp";
                    process.StartInfo.Arguments = "-a " + ipAddress;
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.Start();
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();

                    LogWithTimestamp($"ARP output: {output}", Color.Gray);

                    string[] lines = output.Split('\n');
                    foreach (string line in lines)
                    {
                        if (line.Contains(ipAddress))
                        {
                            string[] parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                            for (int i = 0; i < parts.Length; i++)
                            {
                                if (parts[i].Contains("-"))
                                {
                                    string macAddress = parts[i].Replace("-", ":").ToUpper();
                                    LogWithTimestamp($"Found MAC address: {macAddress}", Color.Gray);
                                    return macAddress;
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                LogWithTimestamp($"Error fetching MAC Address: {ex.Message}", Color.Red);
            }
            return "MAC ADDRESS NOT FOUND";
        }

        private void btnScanPorts_Click(object sender, EventArgs e)
        {
            string targetIp = txtTargetIP.Text;
            txtLogs.AppendText("Starting port scan...\n");
            for (int port = 1; port <= 1024; port++)
            {
                if (IsPortOpen(targetIp, port, 100))
                {
                    txtLogs.AppendText($"Port {port} is open.\n");
                }
            }
            txtLogs.AppendText("Port scan completed.\n");
        }

        private bool IsPortOpen(string ip, int port, int timeout)
        {
            try
            {
                using (var client = new TcpClient())
                {
                    var result = client.BeginConnect(ip, port, null, null);
                    var success = result.AsyncWaitHandle.WaitOne(TimeSpan.FromMilliseconds(timeout));
                    return success;
                }
            }
            catch
            {
                return false;
            }
        }

        // You need to implement these methods
        private string GetLocalIPAddress()
        {
            string hostName = Dns.GetHostName();
            IPAddress[] addresses = Dns.GetHostAddresses(hostName);
            foreach (IPAddress address in addresses)
            {
                if (address.AddressFamily == AddressFamily.InterNetwork)
                {
                    return address.ToString();
                }
            }
            return "127.0.0.1"; // Return localhost if no other IP is found
        }

        private string GetLocalMACAddress()
        {
            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus == OperationalStatus.Up)
                {
                    return BitConverter.ToString(nic.GetPhysicalAddress().GetAddressBytes()).Replace("-", ":");
                }
            }
            return string.Empty;
        }

        private async void btnStartAttack_Click(object sender, EventArgs e)
        {
            string targetIp = txtTargetIP.Text;
            LogWithTimestamp($"Debug: Target IP: {targetIp}", Color.Gray);

            if (!int.TryParse(txtTargetPort.Text, out int targetPort))
            {
                LogWithTimestamp("Debug: Invalid target port.", Color.Red);
                MessageBox.Show("Invalid target port.");
                return;
            }
            LogWithTimestamp($"Debug: Target Port: {targetPort}", Color.Gray);

            if (!int.TryParse(txtRate.Text, out int mbps))
            {
                LogWithTimestamp("Debug: Invalid rate (Mbps).", Color.Red);
                MessageBox.Show("Invalid rate (Mbps).");
                return;
            }
            LogWithTimestamp($"Debug: Rate: {mbps} Mbps", Color.Gray);

            string? attackType = cmbAttackType.SelectedItem?.ToString();
            LogWithTimestamp($"Debug: Attack Type: {attackType}", Color.Gray);

            if (string.IsNullOrEmpty(attackType))
            {
                LogWithTimestamp("Debug: No attack type selected.", Color.Red);
                MessageBox.Show("Please select an attack type.");
                return;
            }

            btnStartAttack.Enabled = false;
            btnStopAttack.Enabled = true;
            cmbAttackType.Enabled = false;
            txtTargetIP.Enabled = false;
            txtTargetPort.Enabled = false;
            txtRate.Enabled = false;

            LogWithTimestamp($"Starting {attackType} attack on {targetIp}:{targetPort} at {mbps} Mbps", Color.Green);

            try
            {
                switch (attackType)
                {
                    case "UDP Flood":
                        LogWithTimestamp("Debug: Calling StartUdpFlood method", Color.Blue);
                        await _attackLogic.StartUdpFlood(targetIp, targetPort, mbps, LogMessage);
                        break;
                    // ... other cases ...
                    default:
                        LogWithTimestamp("Debug: Unknown attack type.", Color.Red);
                        MessageBox.Show("Unknown attack type.");
                        ResetAttackControls();
                        return;
                }

                lblStatus.Text = $"Status: {attackType} in progress";
            }
            catch (Exception ex)
            {
                LogWithTimestamp($"Error starting attack: {ex.Message}", Color.Red);
                LogWithTimestamp($"Debug: Exception stack trace: {ex.StackTrace}", Color.Red);
                ResetAttackControls();
            }
        }

        private void ResetAttackControls()
        {
            btnStartAttack.Enabled = true;
            btnStopAttack.Enabled = false;
            cmbAttackType.Enabled = true;
            txtTargetIP.Enabled = true;
            txtTargetPort.Enabled = true;
            txtRate.Enabled = true;
            lblStatus.Text = "Status: Idle";
        }

        private void btnStopAttack_Click(object sender, EventArgs e)
        {
            _attackLogic.StopAttack();
            LogWithTimestamp("Attack stopped.", Color.Orange);
            ResetAttackControls();
        }

        private void LogMessage(string message)
        {
            if (InvokeRequired)
            {
                Invoke(new Action<string>(LogMessage), message);
            }
            else
            {
                txtLogs.AppendText(message + Environment.NewLine);
                txtLogs.ScrollToCaret();
            }
        }

        private void btnAutoLoadSource_Click(object sender, EventArgs e)
        {
            string sourceIP = GetLocalIPAddress();
            string sourceMAC = GetLocalMACAddress();
            txtSourceIP.Text = sourceIP;
            txtSourceMAC.Text = sourceMAC;
            
            string logMessage = $"Source IP: {sourceIP}, Source MAC: {sourceMAC}";
            LogWithTimestamp(logMessage);
        }

        private void LogWithTimestamp(string message, Color? color = null)
        {
            if (txtLogs.InvokeRequired)
            {
                txtLogs.Invoke(new Action<string, Color?>((msg, clr) =>
                {
                    string timestampedMessage = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] {msg}";
                    txtLogs.SelectionStart = txtLogs.TextLength;
                    txtLogs.SelectionLength = 0;
                    txtLogs.SelectionColor = clr ?? Color.Black;
                    txtLogs.SelectionBackColor = Color.White;
                    txtLogs.AppendText(timestampedMessage + Environment.NewLine);
                    txtLogs.SelectionColor = txtLogs.ForeColor;
                    txtLogs.SelectionBackColor = txtLogs.BackColor;
                    txtLogs.ScrollToCaret();
                    SaveLogToFile(timestampedMessage);
                }), message, color);
            }
            else
            {
                string timestampedMessage = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] {message}";
                txtLogs.SelectionStart = txtLogs.TextLength;
                txtLogs.SelectionLength = 0;
                txtLogs.SelectionColor = color ?? Color.Black;
                txtLogs.SelectionBackColor = Color.White;
                txtLogs.AppendText(timestampedMessage + Environment.NewLine);
                txtLogs.SelectionColor = txtLogs.ForeColor;
                txtLogs.SelectionBackColor = txtLogs.BackColor;
                txtLogs.ScrollToCaret();
                SaveLogToFile(timestampedMessage);
            }
        }

        private void SaveLogToFile(string logMessage)
        {
            string logFilePath = "network_logs.txt";
            try
            {
                using (StreamWriter sw = File.AppendText(logFilePath))
                {
                    sw.WriteLine(logMessage);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error saving log to file: {ex.Message}", "Log Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void ClearLogs()
        {
            txtLogs.Clear();
            LogWithTimestamp("Logs cleared");
        }

        private void SaveLogsManually()
        {
            SaveFileDialog saveFileDialog = new SaveFileDialog();
            saveFileDialog.Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*";
            saveFileDialog.DefaultExt = "txt";
            saveFileDialog.FileName = $"network_logs_{DateTime.Now:yyyyMMdd_HHmmss}.txt";

            if (saveFileDialog.ShowDialog() == DialogResult.OK)
            {
                try
                {
                    File.WriteAllText(saveFileDialog.FileName, txtLogs.Text);
                    MessageBox.Show("Logs saved successfully!", "Save Logs", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error saving logs: {ex.Message}", "Save Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        private void btnClearLogs_Click(object sender, EventArgs e)
        {
            ClearLogs();
        }

        private void btnSaveLogs_Click(object sender, EventArgs e)
        {
            SaveLogsManually();
        }

        private LinearGradientBrush CreateGradientBrush(Color color1, Color color2, float angle)
        {
            return new LinearGradientBrush(new Point(0, 0), new Point(1, 1), color1, color2)
            {
                LinearColors = new Color[] { color1, color2 },
                GammaCorrection = true
            };
        }

        private async void btnFindPort_Click(object sender, EventArgs e)
        {
            string targetIp = txtTargetIP.Text;
            btnFindPort.Enabled = false;
            LogWithTimestamp("Starting port scan...", Color.Blue);
            
            int openPort = await FindFirstOpenPortAsync(targetIp);
            
            if (openPort != -1)
            {
                txtTargetPort.Text = openPort.ToString();
                LogWithTimestamp($"First open TCP port found: {openPort}", Color.Green);
            }
            else
            {
                txtTargetPort.Text = "No open port found";
                LogWithTimestamp("No open TCP ports found", Color.Yellow);
            }
            
            btnFindPort.Enabled = true;
        }

        private async Task<int> FindFirstOpenPortAsync(string ipAddress)
        {
            int[] commonPorts = { 22, 80, 443, 21, 25, 3389, 110, 143, 53, 23, 445, 139, 8080, 1723, 111 };
            
            using (var client = new TcpClient())
            {
                foreach (int port in commonPorts)
                {
                    try
                    {
                        await client.ConnectAsync(ipAddress, port, new CancellationTokenSource(500).Token);
                        client.Close();
                        LogWithTimestamp($"Port {port} is open", Color.Green);
                        return port;
                    }
                    catch (OperationCanceledException)
                    {
                        LogWithTimestamp($"Connection to port {port} timed out", Color.Yellow);
                    }
                    catch (SocketException)
                    {
                        LogWithTimestamp($"Port {port} is closed or filtered", Color.Gray);
                    }
                    await Task.Delay(10); // Small delay to prevent UI freezing
                }
            }
            return -1;
        }
    }
}