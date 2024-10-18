#ifndef TCPSYNFLOOD_H
#define TCPSYNFLOOD_H

#ifdef __cplusplus
extern "C" {
#endif

int tcp_syn_flood(const char *source_ip, const char *target_ip, int target_port, int num_packets, const char *iface);

#ifdef __cplusplus
}
#endif

#endif // TCPSYNFLOOD_H
