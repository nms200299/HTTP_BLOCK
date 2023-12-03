#include <protocolHeader.h>
#include <pcap.h>
#include <srcLinkHeader.h>
#include <netinet/tcp.h>

#define TLS_HANDSHAKE 0x16

void recvTcp(const u_char *packet){
    tcphdr *tcph = (tcphdr *)packet;
    u_char *tcpPaylaod = (u_char *)(packet+(tcph->th_off*4));

    if (*tcpPaylaod == TLS_HANDSHAKE){
        //printf("tls_hand\n");
        recvTls(tcpPaylaod);

    }

}
