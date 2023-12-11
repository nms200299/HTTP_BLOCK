#include <protocolHeader.h>
#include <pcap.h>
#include <srcLinkHeader.h>
#include <netinet/tcp.h>
#include <string.h>
#define TLS_HANDSHAKE 0x16

uint8_t recvTcp(const u_char *packet, char *blockDomain[]){
    tcphdr *tcph = (tcphdr *)packet;
    u_char *tcpPaylaod = (u_char *)(packet+(tcph->th_off*4));

    if (*tcpPaylaod == TLS_HANDSHAKE){
        return recvTls(tcpPaylaod, blockDomain);
    } else {
        for (uint8_t diffLoop=0; diffLoop <= 9; diffLoop++){
            if (blockDomain[diffLoop] != NULL){
                if (strcasestr((const char *)tcpPaylaod, (const char *)(blockDomain[diffLoop])) != NULL){
                    printf("HTTP HOST\n");
                    return 1;
                }
            } else {
                break;
            }
        }
    }
    return 0;
}
