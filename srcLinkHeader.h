#pragma once
#include <stdint.h>
#include <pcap.h>
#include <protocolHeader.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

void myinfo(uint8_t myMac[6], uint8_t myIp[4]);

void *arpScan(void *args);
void *arpSpoof(void *args);


void sendArpReq(pcap_t* pcapH, uint8_t (*myMac)[6], uint8_t (*myIp)[4], uint8_t targetIp);
void sendRelay(pcap_t* pcapH, u_char *packet, bpf_u_int32 caplen, uint8_t (*myMac)[6], uint8_t (*dstMac)[6]);
void sendTcpClose(pcap_t* pcapH, u_char *packet, char *blockStr);

void recvArpRep(const u_char* packet, uint8_t ipTable[256][6]);
uint8_t recvDhcp(const u_char* packet);
uint8_t recvTcp(const u_char *packet, char *blockDomain[]);
uint8_t recvTls(const u_char *packet, char *blockDomain[]);

uint16_t calcIpChksum(struct ip *iph);
uint16_t calcTcpChksum(ipPseudoHeader *iph, tcpPseudoHeader *tcph, uint8_t *data, int dataLen);
