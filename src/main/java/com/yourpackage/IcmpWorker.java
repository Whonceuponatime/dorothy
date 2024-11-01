package com.yourpackage;

public class IcmpWorker {
    public static void main(String[] args) {
        if (args.length != 3) {
            System.err.println("Usage: IcmpWorker <targetIp> <bytesPerSecond> <processId>");
            System.exit(1);
        }

        String targetIp = args[0];
        long bytesPerSecond = Long.parseLong(args[1]);
        int processId = Integer.parseInt(args[2]);

        IcmpFlood flood = new IcmpFlood(targetIp, bytesPerSecond);
        flood.startWorker();
    }
}
