#pragma once
#include <stdint.h>

// ▼ myInfo.cpp
void myinfo(uint8_t myMac[6], uint8_t myIp[4]);

// ▼ arpScan.cpp
void *arpScan(void *args);

// ▼ recvArpRep.cpp
void *recvArpRep(const u_char* packet, uint8_t ipTable[256][6]);

// ▼ recvDhcp.cpp
uint8_t recvDhcp(const u_char* packet);
