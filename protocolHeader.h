#include <stdint.h>

struct etherHeader{
    uint8_t dhost[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint8_t shost[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint16_t type = 0x0608; // little endian
} __attribute__ ((__packed__));

struct arpHeader{
    uint16_t h_type = 0x0100;
    uint16_t p_type = 0x0008; // little endian
    uint8_t h_size = 6;
    uint8_t p_size = 4;
    uint16_t op = 0x0100;
    uint8_t sha[6] = {0,}; //my mac
    uint8_t sip[4] = {0,}; //my IP
    uint8_t dha[6] = {0,}; //00:00:00:00:00:00
    uint8_t dip[4] = {0,}; //scanning target IP
} __attribute__ ((__packed__));

struct dhcpHeader{
    uint8_t op;             // 메시지 종류 (부팅 요청, 부팅 응답 등)
    uint8_t htype;          // 하드웨어 주소 타입
    uint8_t hlen;           // 하드웨어 주소 길이
    uint8_t hops;           // Relay Agent 사용시 거친 홉 수
    uint32_t xid;           // 트랜잭션 ID
    uint16_t secs;          // 부팅 후 경과 시간 (초 단위)
    uint16_t flags;         // 플래그
    uint32_t ciaddr;        // 클라이언트 IP 주소
    uint32_t yiaddr;        // 할당된 IP 주소
    uint32_t siaddr;        // 부트 서버 IP 주소
    uint32_t giaddr;        // Relay Agent IP 주소
    uint8_t chaddr[16];     // 클라이언트 하드웨어 주소
    uint8_t serverName[64]; // Server Name
    uint8_t btFileName[128];// Boot File Name
    uint8_t magicCookie[4]; // Magic Cookie
    uint8_t options[308];   // 옵션
} __attribute__ ((__packed__));


struct arpPacket{
    struct etherHeader ether;
    struct arpHeader arp;
} __attribute__ ((__packed__));
