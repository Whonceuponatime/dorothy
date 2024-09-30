namespace Dorothy;

partial class Form1
{
    /// <summary>
    ///  Required designer variable.
    /// </summary>
    private System.ComponentModel.IContainer components = null;

    /// <summary>
    ///  Clean up any resources being used.
    /// </summary>
    /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
    protected override void Dispose(bool disposing)
    {
        if (disposing && (components != null))
        {
            components.Dispose();
        }
        base.Dispose(disposing);
    }

    #region Windows Form Designer generated code

    /// <summary>
    ///  Required method for Designer support - do not modify
    ///  the contents of this method with the code editor.
    /// </summary>
    private void InitializeComponent()
    {
        this.txtTargetIP = new System.Windows.Forms.TextBox();
        this.txtMACAddress = new System.Windows.Forms.TextBox();
        this.txtTargetPort = new System.Windows.Forms.TextBox();
        this.txtRate = new System.Windows.Forms.TextBox();
        this.cmbAttackType = new System.Windows.Forms.ComboBox();
        this.btnPing = new System.Windows.Forms.Button();
        this.btnGetMAC = new System.Windows.Forms.Button();
        this.btnFindPort = new System.Windows.Forms.Button();
        this.btnStartAttack = new System.Windows.Forms.Button();
        this.btnStopAttack = new System.Windows.Forms.Button();
        this.lblStatus = new System.Windows.Forms.Label();
        this.chartNetworkLoad = new System.Windows.Forms.DataVisualization.Charting.Chart();
        this.txtSourceIP = new System.Windows.Forms.TextBox();
        this.txtSourceMAC = new System.Windows.Forms.TextBox();
        this.btnAutoLoadSource = new System.Windows.Forms.Button();
        this.btnClearLogs = new System.Windows.Forms.Button();
        this.btnSaveLogs = new System.Windows.Forms.Button();
        this.txtLogs = new System.Windows.Forms.RichTextBox();

        // Set up the form
        this.SuspendLayout();
        this.Text = "Network Attack Simulator";
        this.ClientSize = new System.Drawing.Size(800, 600);

        // Source IP
        this.txtSourceIP.Location = new System.Drawing.Point(20, 20);
        this.txtSourceIP.Size = new System.Drawing.Size(200, 23);
        this.txtSourceIP.ReadOnly = true;
        this.Controls.Add(this.txtSourceIP);

        // Source MAC
        this.txtSourceMAC.Location = new System.Drawing.Point(20, 50);
        this.txtSourceMAC.Size = new System.Drawing.Size(200, 23);
        this.txtSourceMAC.ReadOnly = true;
        this.Controls.Add(this.txtSourceMAC);

        // Target IP
        this.txtTargetIP.Location = new System.Drawing.Point(20, 80);
        this.txtTargetIP.Size = new System.Drawing.Size(200, 23);
        this.Controls.Add(this.txtTargetIP);

        // Ping button
        this.btnPing.Location = new System.Drawing.Point(230, 80);
        this.btnPing.Size = new System.Drawing.Size(75, 23);
        this.btnPing.Text = "Ping";
        this.Controls.Add(this.btnPing);
        this.btnPing.Click += new System.EventHandler(this.btnPing_Click);

        // MAC Address
        this.txtMACAddress.Location = new System.Drawing.Point(20, 110);
        this.txtMACAddress.Size = new System.Drawing.Size(200, 23);
        this.txtMACAddress.ReadOnly = true;
        this.Controls.Add(this.txtMACAddress);

        // Get MAC button
        this.btnGetMAC.Location = new System.Drawing.Point(230, 110);
        this.btnGetMAC.Size = new System.Drawing.Size(75, 23);
        this.btnGetMAC.Text = "Get MAC";
        this.Controls.Add(this.btnGetMAC);
        this.btnGetMAC.Click += new System.EventHandler(this.btnGetMAC_Click);

        // Target Port
        this.txtTargetPort.Location = new System.Drawing.Point(20, 140);
        this.txtTargetPort.Size = new System.Drawing.Size(200, 23);
        this.Controls.Add(this.txtTargetPort);

        // Find Port button
        this.btnFindPort.Location = new System.Drawing.Point(230, 140);
        this.btnFindPort.Size = new System.Drawing.Size(75, 23);
        this.btnFindPort.Text = "Find Port";
        this.Controls.Add(this.btnFindPort);
        this.btnFindPort.Click += new System.EventHandler(this.btnFindPort_Click);

        // Rate (Mbps)
        this.txtRate.Location = new System.Drawing.Point(20, 170);
        this.txtRate.Size = new System.Drawing.Size(100, 23);
        this.Controls.Add(this.txtRate);

        // Mbps label
        Label lblMbps = new Label();
        lblMbps.Text = "Mbps";
        lblMbps.Location = new System.Drawing.Point(130, 173);
        lblMbps.AutoSize = true;
        this.Controls.Add(lblMbps);

        // Attack Type ComboBox
        this.cmbAttackType.Location = new System.Drawing.Point(20, 200);
        this.cmbAttackType.Size = new System.Drawing.Size(200, 23);
        this.cmbAttackType.DropDownStyle = ComboBoxStyle.DropDownList;
        this.Controls.Add(this.cmbAttackType);
        this.cmbAttackType.Items.Add("UDP Flood");
        this.cmbAttackType.Items.Add("TCP SYN Flood");
        this.cmbAttackType.Items.Add("ICMP Flood");

        // Start Attack button
        this.btnStartAttack.Location = new System.Drawing.Point(20, 230);
        this.btnStartAttack.Size = new System.Drawing.Size(100, 23);
        this.btnStartAttack.Text = "Start Attack";
        this.Controls.Add(this.btnStartAttack);
        this.btnStartAttack.Click += new System.EventHandler(this.btnStartAttack_Click);

        // Stop Attack button
        this.btnStopAttack.Location = new System.Drawing.Point(130, 230);
        this.btnStopAttack.Size = new System.Drawing.Size(100, 23);
        this.btnStopAttack.Text = "Stop Attack";
        this.Controls.Add(this.btnStopAttack);
        this.btnStopAttack.Click += new System.EventHandler(this.btnStopAttack_Click);
        this.btnStopAttack.Enabled = false; // Initially disabled

        // Status label
        this.lblStatus.Location = new System.Drawing.Point(20, 260);
        this.lblStatus.AutoSize = true;
        this.lblStatus.Text = "Status: Idle";
        this.Controls.Add(this.lblStatus);

        // Network Load Chart
        this.chartNetworkLoad.Location = new System.Drawing.Point(20, 290);
        this.chartNetworkLoad.Size = new System.Drawing.Size(760, 290);
        this.chartNetworkLoad.ChartAreas.Add(new System.Windows.Forms.DataVisualization.Charting.ChartArea());
        this.chartNetworkLoad.Series.Add(new System.Windows.Forms.DataVisualization.Charting.Series());
        this.chartNetworkLoad.Titles.Add("Network Load");
        this.Controls.Add(this.chartNetworkLoad);

        // Logs TextBox
        this.txtLogs.Location = new System.Drawing.Point(320, 20);
        this.txtLogs.Size = new System.Drawing.Size(450, 200);
        this.txtLogs.ReadOnly = true;
        this.txtLogs.ScrollBars = System.Windows.Forms.RichTextBoxScrollBars.Vertical;
        this.Controls.Add(this.txtLogs);

        // Auto Load Source button
        this.btnAutoLoadSource.Location = new System.Drawing.Point(230, 35);
        this.btnAutoLoadSource.Size = new System.Drawing.Size(75, 23);
        this.btnAutoLoadSource.Text = "Auto Load";
        this.Controls.Add(this.btnAutoLoadSource);
        this.btnAutoLoadSource.Click += new System.EventHandler(this.btnAutoLoadSource_Click);

        // Clear Logs button
        this.btnClearLogs.Location = new System.Drawing.Point(320, 230);
        this.btnClearLogs.Size = new System.Drawing.Size(75, 23);
        this.btnClearLogs.Text = "Clear Logs";
        this.Controls.Add(this.btnClearLogs);
        this.btnClearLogs.Click += new System.EventHandler(this.btnClearLogs_Click);

        // Save Logs button
        this.btnSaveLogs.Location = new System.Drawing.Point(405, 230);
        this.btnSaveLogs.Size = new System.Drawing.Size(75, 23);
        this.btnSaveLogs.Text = "Save Logs";
        this.Controls.Add(this.btnSaveLogs);
        this.btnSaveLogs.Click += new System.EventHandler(this.btnSaveLogs_Click);

        this.ResumeLayout(false);
        this.PerformLayout();
    }

    #endregion

    private System.Windows.Forms.TextBox txtTargetIP;
    private System.Windows.Forms.TextBox txtMACAddress;
    private System.Windows.Forms.TextBox txtTargetPort;
    private System.Windows.Forms.TextBox txtRate;
    private System.Windows.Forms.ComboBox cmbAttackType;
    private System.Windows.Forms.Button btnPing;
    private System.Windows.Forms.Button btnGetMAC;
    private System.Windows.Forms.Button btnFindPort;
    private System.Windows.Forms.Button btnStartAttack;
    private System.Windows.Forms.Button btnStopAttack;
    private System.Windows.Forms.Label lblStatus;
    private System.Windows.Forms.DataVisualization.Charting.Chart chartNetworkLoad;
    private System.Windows.Forms.RichTextBox txtLogs;
    private System.Windows.Forms.TextBox txtSourceIP;
    private System.Windows.Forms.TextBox txtSourceMAC;
    private System.Windows.Forms.Button btnAutoLoadSource;
    private System.Windows.Forms.Button btnClearLogs;
    private System.Windows.Forms.Button btnSaveLogs;
}