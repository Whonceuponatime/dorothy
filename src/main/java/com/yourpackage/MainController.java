package com.yourpackage;

import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.fxml.FXML;
import javafx.scene.chart.LineChart;
import javafx.scene.chart.NumberAxis;
import javafx.scene.chart.XYChart;
import javafx.scene.control.*;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.ArrayList;
import java.util.Enumeration;
import java.io.IOException;

public class MainController {
    private Jenkins jenkinsTool;

    @FXML private TextField sourceIpField;
    @FXML private TextField sourceMacField;
    @FXML private TextField ipAddressField;
    @FXML private TextField portField;
    @FXML private TextField targetMbpsField;
    @FXML private TextField macAddressField;
    @FXML private ComboBox<String> attackTypeComboBox;
    @FXML private Button startButton;
    @FXML private Button stopButton;
    @FXML private Button pingButton;
    @FXML private Button getMacButton;
    @FXML private Label statusLabel;
    @FXML private TextArea logArea;
    @FXML private Button findOpenPortButton;
    @FXML private ComboBox<String> networkCardComboBox;
    @FXML private Button loadSourceInfoButton;

    @FXML private LineChart<Number, Number> networkLoadChart;
    @FXML private NumberAxis xAxis;
    @FXML private NumberAxis yAxis;
    private XYChart.Series<Number, Number> dataSeries;
    private long startTime;

    @FXML
    public void initialize() {
        jenkinsTool = new Jenkins();
        attackTypeComboBox.setItems(FXCollections.observableArrayList("TCP SYN Flood"));
        populateNetworkCardComboBox();

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

    // Method to populate the network card ComboBox
    @FXML
    public void populateNetworkCardComboBox() {
        try {
            List<String> devices = jenkinsTool.getNetworkDevices();
            networkCardComboBox.getItems().clear();
            networkCardComboBox.getItems().addAll(devices);
            log("Available network devices loaded successfully.");
        } catch (Exception e) {
            log("Error retrieving network interfaces: " + e.getMessage());
        }
    }

    @FXML
    public void pingTargetIP() {
        try {
            String ip = ipAddressField.getText();
            if (ip.isEmpty()) {
                log("Please enter a valid IP address.");
                return;
            }
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

    @FXML
    public void startAttack() {
        // Validation of input fields
        if (ipAddressField.getText().isEmpty() || portField.getText().isEmpty() || targetMbpsField.getText().isEmpty() ||
            sourceIpField.getText().isEmpty() || sourceMacField.getText().isEmpty() || attackTypeComboBox.getValue() == null || networkCardComboBox.getValue() == null) {
            log("All fields must be filled to start the attack.");
            return;
        }

        jenkinsTool.stopAttack(); // Ensure any previous attack is stopped
        String attackType = attackTypeComboBox.getValue();
        String targetIp = ipAddressField.getText();
        int targetPort = Integer.parseInt(portField.getText());
        int targetMbps = Integer.parseInt(targetMbpsField.getText());

        String sourceIp = sourceIpField.getText();
        String sourceMac = sourceMacField.getText();
        String networkCard = networkCardComboBox.getValue();

        log("Preparing to start attack: Type = " + attackType + ", Target IP = " + targetIp + ", Source IP = " + sourceIp);

        // Reset chart data
        dataSeries.getData().clear();
        startTime = System.currentTimeMillis();

        if ("TCP SYN Flood".equals(attackType)) {
            log("Starting TCP SYN flood attack...");
            new Thread(() -> {
                int result = jenkinsTool.tcpSynFloodJNI(targetIp, targetPort, targetMbps, sourceIp, sourceMac, networkCard);
                Platform.runLater(() -> {
                    if (result == 0) {
                        log("TCP SYN flood attack completed successfully.");
                    } else {
                        log("Error occurred during TCP SYN flood attack.");
                    }
                    stopAttack(); // Automatically stop after execution
                });
            }).start();
        } else {
            log("Unsupported attack type selected.");
            return;
        }

        statusLabel.setText("Status: Attack Running");
        startButton.setDisable(true);
        stopButton.setDisable(false);
    }

    @FXML
    public void stopAttack() {
        log("Stopping the attack...");
        jenkinsTool.nativeStopAttack();
        statusLabel.setText("Status: Attack Stopped");
        startButton.setDisable(false);
        stopButton.setDisable(true);
        log("Attack stopped");
    }

    @FXML
    public void findOpenPort() {
        String ip = ipAddressField.getText();
        if (ip.isEmpty()) {
            log("Please enter a target IP address to scan for open ports.");
            return;
        }
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

    @FXML
    private void loadSourceInfo() {
        try {
            InetAddress localHost = InetAddress.getLocalHost();
            String sourceIp = localHost.getHostAddress();
            sourceIpField.setText(sourceIp);

            NetworkInterface ni = NetworkInterface.getByInetAddress(localHost);
            byte[] hardwareAddress = ni.getHardwareAddress();
            if (hardwareAddress == null) {
                log("No hardware address found for local host.");
                return;
            }
            String sourceMac = String.format("%02X:%02X:%02X:%02X:%02X:%02X",
                    hardwareAddress[0], hardwareAddress[1], hardwareAddress[2],
                    hardwareAddress[3], hardwareAddress[4], hardwareAddress[5]);
            sourceMacField.setText(sourceMac);

            log("Source information loaded successfully.");
        } catch (Exception e) {
            log("Error loading source information: " + e.getMessage());
        }
    }

    private void log(String message) {
        String timestamp = java.time.LocalDateTime.now().format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        Platform.runLater(() -> {
            logArea.appendText(timestamp + " - " + message + "\n");
            logArea.setScrollTop(Double.MAX_VALUE);
        });
    }

    private void updateChart(double elapsedTimeSeconds, double actualMbps) {
        Platform.runLater(() -> {
            dataSeries.getData().add(new XYChart.Data<>(elapsedTimeSeconds, actualMbps));
            if (elapsedTimeSeconds > 60) {
                xAxis.setLowerBound(elapsedTimeSeconds - 60);
                xAxis.setUpperBound(elapsedTimeSeconds);
            }
        });
    }
}
