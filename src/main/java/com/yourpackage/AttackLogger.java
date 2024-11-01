package com.yourpackage;

import javafx.application.Platform;
import javafx.scene.control.TextArea;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class AttackLogger {
    private static final int LOG_INTERVAL_MS = 1000;
    private final String attackType;
    private final String targetIp;
    private final String sourceIp;
    private final String sourceMac;
    private final String targetMac;
    private final long targetBytesPerSecond;
    private long lastLogTime = 0;
    private long attackStartTime;
    private final TextArea logArea;

    public AttackLogger(String attackType, String targetIp, String targetMac, String sourceIp, 
                       String sourceMac, long targetBytesPerSecond, TextArea logArea) {
        this.attackType = attackType;
        this.targetIp = targetIp;
        this.targetMac = targetMac;
        this.sourceIp = sourceIp;
        this.sourceMac = sourceMac;
        this.targetBytesPerSecond = targetBytesPerSecond;
        this.logArea = logArea;
        this.attackStartTime = System.currentTimeMillis();
        
        String startMessage = String.format("[%s] Attack Details:\n" +
            "Type: %s\n" +
            "Source: %s (%s)\n" +
            "Target: %s (%s)\n" +
            "Mbps: %d\n" +
            "Status: Started\n",
            LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_TIME),
            attackType,
            sourceIp,
            sourceMac,
            targetIp,
            targetMac,
            targetBytesPerSecond / 125000L
        );
        logEvent(startMessage);
    }

    public void logStats(double currentRate, double targetRate, long totalPackets, double totalDataSent) {
        long currentTime = System.currentTimeMillis();
        if (currentTime - lastLogTime >= LOG_INTERVAL_MS) {
            String performance = currentRate < targetRate * 0.8 ? "BELOW TARGET" : 
                               currentRate > targetRate * 1.2 ? "EXCEEDING TARGET" : "ON TARGET";
            
            String stats = String.format("[%s] Attack Progress:\n" +
                "Source: %s (%s)\n" +
                "Target: %s (%s)\n" +
                "Attack Type: %s\n" +
                "Current Rate: %.2f Mbps\n" +
                "Target Rate: %.2f Mbps\n" +
                "Total Data Sent: %.2f MB\n" +
                "Packets Sent: %d\n" +
                "Performance: %s\n" +
                "Duration: %ds\n",
                LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_TIME),
                sourceIp,
                sourceMac,
                targetIp,
                targetMac,
                attackType,
                currentRate,
                targetRate,
                totalDataSent / (1024.0 * 1024.0),
                totalPackets,
                performance,
                (currentTime - attackStartTime) / 1000
            );
            
            logEvent(stats);
            lastLogTime = currentTime;
        }
    }

    public void logStop() {
        long duration = (System.currentTimeMillis() - attackStartTime) / 1000;
        String stopMessage = String.format("[%s] Attack Terminated:\n" +
            "Type: %s\n" +
            "Source: %s (%s)\n" +
            "Target: %s (%s)\n" +
            "Duration: %d seconds\n",
            LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_TIME),
            attackType,
            sourceIp,
            sourceMac,
            targetIp,
            targetMac,
            duration
        );
        logEvent(stopMessage);
    }

    public void logEvent(String message) {
        Platform.runLater(() -> {
            logArea.appendText(message + "\n\n");
            logArea.setScrollTop(Double.MAX_VALUE);
        });
    }
} 