package com.yourpackage;

import javafx.fxml.FXML;
import javafx.scene.control.TextField;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.ComboBox;
import javafx.collections.FXCollections;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import javafx.scene.control.TextArea;
import javafx.application.Platform;
import java.net.InetSocketAddress;
import java.io.IOException;
import javafx.scene.control.ToggleButton;
import javafx.scene.layout.HBox;
import javafx.scene.chart.LineChart;
import javafx.scene.chart.NumberAxis;
import javafx.scene.chart.XYChart;

public class MainController {
    private Jenkins jenkinsTool;

    @FXML private TextField ipAddressField;
    @FXML private TextField portField;
    @FXML private TextField mbpsField;
    @FXML private TextField macAddressField;
    @FXML private ComboBox<String> attackTypeComboBox;
    @FXML private Button startButton;
    @FXML private Button stopButton;
    @FXML private Button pingButton;
    @FXML private Button getMacButton;
    @FXML private Label statusLabel;
    @FXML private TextArea logArea;
    @FXML private Button findOpenPortButton;

    @FXML private HBox rateBox;
    private boolean isMbps = true;

    @FXML private LineChart<Number, Number> networkLoadChart;
    @FXML private NumberAxis xAxis;
    @FXML private NumberAxis yAxis;
    private XYChart.Series<Number, Number> dataSeries;
    private long startTime;

    @FXML private TextField sourceIpField;
    @FXML private TextField sourceMacField;
    @FXML private Button loadSourceInfoButton;

    @FXML
    public void initialize() {
        jenkinsTool = new Jenkins();
        jenkinsTool.setLogArea(logArea);
        attackTypeComboBox.setItems(FXCollections.observableArrayList("UDP Flood", "TCP SYN Flood", "ICMP Flood"));

        // Set up the chart
        xAxis = new NumberAxis(0, 60, 10);
        yAxis = new NumberAxis();
        xAxis.setLabel("Time (seconds)");
        yAxis.setLabel("Network Load (Mbps)");
        networkLoadChart.setTitle("Network Load");
        networkLoadChart.setAnimated(false);
        dataSeries = new XYChart.Series<>();
        dataSeries.setName("Network Load");
        networkLoadChart.getData().add(dataSeries);
    }

    @FXML
    public void pingTargetIP() {
        try {
            String ip = ipAddressField.getText();
            InetAddress address = InetAddress.getByName(ip);
            log("Pinging " + ip + "...");
            boolean reachable = address.isReachable(5000);
            String result = reachable ? "Ping successful" : "Ping failed";
            log(result);
            statusLabel.setText(result);
        } catch (Exception e) {
            log("Error: " + e.getMessage());
            statusLabel.setText("Error: " + e.getMessage());
        }
    }

    @FXML
    private void getMacAddress() {
        String targetIp = ipAddressField.getText();
        if (targetIp.isEmpty()) {
            log("Please enter a target IP address.");
            return;
        }
        String macAddress = jenkinsTool.getMacAddress(targetIp);
        if (macAddress != null) {
            macAddressField.setText(macAddress);
        } else {
            macAddressField.setText("MAC address not found");
        }
    }

    public void startAttack() {
        jenkinsTool.resetAttack();
        String attackType = attackTypeComboBox.getValue();
        String targetIp = ipAddressField.getText();
        int targetPort = Integer.parseInt(portField.getText());
        long targetBytesPerSecond = Long.parseLong(targetMbpsField.getText()) * 125000L; // Convert Mbps to bytes/sec

        // Reset chart data
        dataSeries.getData().clear();
        startTime = System.currentTimeMillis();

        switch (attackType) {
            case "UDP Flood":
                // Existing UDP flood implementation
                break;
            case "TCP SYN Flood":
                jenkinsTool.tcpSynFlood(targetIp, targetPort, targetBytesPerSecond, () -> {
                    long currentTime = System.currentTimeMillis();
                    double elapsedTimeSeconds = (currentTime - startTime) / 1000.0;
                    double actualMbps = targetBytesPerSecond * 8.0 / 1_000_000.0; // Convert bytes/sec to Mbps
                    updateChart(elapsedTimeSeconds, actualMbps);
                });
                break;
            case "ICMP Flood":
                // Existing ICMP flood implementation
                break;
            default:
                log("Unknown attack type selected.");
        }
    }

    public void stopAttack() {
        jenkinsTool.stopAttack();
        statusLabel.setText("Status: Attack Stopped");
        startButton.setDisable(false);
        stopButton.setDisable(true);
        log("Attack stopped");
    }

    @FXML
    public void findOpenPort() {
        String ip = ipAddressField.getText();
        log("Searching for open ports on " + ip);
        int[] commonPorts = {80, 443, 22, 21, 25, 3306, 8080, 1433, 3389, 5432};
        for (int port : commonPorts) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(ip, port), 100);
                portField.setText(String.valueOf(port));
                String message = "Open port found: " + port;
                log(message);
                statusLabel.setText(message);
                return;
            } catch (IOException e) {
                // Port is not open, continue to next
            }
        }
        String message = "No open ports found";
        log(message);
        statusLabel.setText(message);
    }

    private void log(String message) {
        String timestamp = java.time.LocalDateTime.now().format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        Platform.runLater(() -> {
            logArea.appendText(timestamp + " - " + message + "\n");
            logArea.setScrollTop(Double.MAX_VALUE);
        });
    }

    public void scanPorts(String targetIp) {
        log("Starting port scan on " + targetIp);
        for (int port = 1; port <= 65535; port++) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(targetIp, port), 100);
                String message = "Port " + port + " is open";
                log(message);
                statusLabel.setText(message);
            } catch (IOException e) {
                // Port is not open, continue to next
            }
        }
        String message = "Port scan completed";
        log(message);
        statusLabel.setText(message);
    }

    @FXML private TextField targetMbpsField;

    private void updateChart(double elapsedTimeSeconds, double actualMbps) {
        Platform.runLater(() -> {
            dataSeries.getData().add(new XYChart.Data<>(elapsedTimeSeconds, actualMbps));
            if (dataSeries.getData().size() > 60) {
                dataSeries.getData().remove(0);
            }
            xAxis.setLowerBound(Math.max(0, elapsedTimeSeconds - 60));
            xAxis.setUpperBound(Math.max(60, elapsedTimeSeconds));
        });
    }

    @FXML
    private void loadSourceInfo() {
        try {
            InetAddress localHost = InetAddress.getLocalHost();
            String sourceIp = localHost.getHostAddress();
            sourceIpField.setText(sourceIp);

            NetworkInterface ni = NetworkInterface.getByInetAddress(localHost);
            byte[] hardwareAddress = ni.getHardwareAddress();
            String sourceMac = String.format("%02X:%02X:%02X:%02X:%02X:%02X", 
                hardwareAddress[0], hardwareAddress[1], hardwareAddress[2], 
                hardwareAddress[3], hardwareAddress[4], hardwareAddress[5]);
            sourceMacField.setText(sourceMac);

            // Update the Jenkins class with the new source information
            jenkinsTool.setSourceIp(sourceIp);
            jenkinsTool.setSourceMac(hardwareAddress);

            log("Source information loaded successfully.");
        } catch (Exception e) {
            log("Error loading source information: " + e.getMessage());
        }
    }
}