#pragma once
#include <stdint.h>
#include <pcap.h>

void myinfo(uint8_t myMac[6], uint8_t myIp[4]);


void *arpScan(void *args);
void *arpSpoof(void *args);


void sendArpReq(pcap_t* pcapH, uint8_t (*myMac)[6], uint8_t (*myIp)[4], uint8_t targetIp);
void sendRelay(pcap_t* pcapH, u_char *packet, bpf_u_int32 caplen, uint8_t (*myMac)[6], uint8_t (*gwMac)[6]);

void recvArpRep(const u_char* packet, uint8_t ipTable[256][6]);
uint8_t recvDhcp(const u_char* packet);
void recvTcp(const u_char* packet);
void recvTls(const u_char *packet);
