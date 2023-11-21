#include <protocolHeader.h>
#include <pcap.h>
#include <srcLinkHeader.h>

#define TLS_HANDSHAKE 0x16

void recvTcp(const u_char *packet){
    tcpHeader *tcph = (tcpHeader *)packet;
    u_char *tcpPaylaod = (u_char *)(packet+sizeof(tcpHeader));

    if (*tcpPaylaod == TLS_HANDSHAKE){
        recvTls(tcpPaylaod);
    }

}
