#include <protocolHeader.h>
#include <srcLinkHeader.h>

#include <pcap.h>
#include <string.h> // memcpy
#include <stdlib.h> // exit
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>

struct tcpPacket {
    struct ether_header ep;
    struct ip iph;
    struct tcphdr tcph;
}__attribute__ ((__packed__));

struct finPacket {
    struct tcpPacket pk;
    char blockStr[100];
}__attribute__ ((__packed__));



void sendTcpClose(pcap_t* pcapH, u_char *packet, char *blockStr){
    finPacket tcpFinPacket;
    tcpPacket tcpRstPacket;

    ether_header *ethh = (struct ether_header *)packet;
    ip *iph = (struct ip *)(packet+sizeof(ether_header));
    tcphdr *tcph = (struct tcphdr *)(packet+sizeof(ether_header)+(iph->ip_hl*4));
    ipPseudoHeader  ipPseh;
    tcpPseudoHeader tcpPseh;
    int blockStrLen = strlen(blockStr);

    // ▼ TCP_FIN_PACKET (To. Device)
    memcpy(tcpFinPacket.pk.ep.ether_dhost, ethh->ether_shost, 6);
    memcpy(tcpFinPacket.pk.ep.ether_shost, ethh->ether_dhost, 6);
    tcpFinPacket.pk.ep.ether_type = htons(0x0800);

    tcpFinPacket.pk.iph.ip_hl = 5;// htons -> reverse
    tcpFinPacket.pk.iph.ip_v = 4; // htons -> reverse
    tcpFinPacket.pk.iph.ip_p = IPPROTO_TCP;
    tcpFinPacket.pk.iph.ip_off = 0;
    tcpFinPacket.pk.iph.ip_len = htons((int)(sizeof(struct ip) + sizeof(struct tcphdr)) + blockStrLen);
    tcpFinPacket.pk.iph.ip_ttl = 128;
    tcpFinPacket.pk.iph.ip_src = iph->ip_dst;
    tcpFinPacket.pk.iph.ip_dst = iph->ip_src;
    tcpFinPacket.pk.iph.ip_sum = 0;
    tcpFinPacket.pk.iph.ip_sum = htons(calcIpChksum(&(tcpFinPacket.pk.iph)));

    tcpFinPacket.pk.tcph.th_off = 5;
    tcpFinPacket.pk.tcph.ack = 1;
    tcpFinPacket.pk.tcph.syn = 0;
    tcpFinPacket.pk.tcph.fin = 1;
    tcpFinPacket.pk.tcph.th_urp = 0;
    tcpFinPacket.pk.tcph.th_sport = tcph->th_dport;
    tcpFinPacket.pk.tcph.th_dport = tcph->th_sport;
    tcpFinPacket.pk.tcph.th_seq = tcph->th_ack;
    tcpFinPacket.pk.tcph.th_ack = htonl(ntohl(tcph->th_seq) + blockStrLen);

    ipPseh.sIp = ntohl(tcpFinPacket.pk.iph.ip_src.s_addr);
    ipPseh.dIp = ntohl(tcpFinPacket.pk.iph.ip_dst.s_addr);
    ipPseh.protocol = tcpFinPacket.pk.iph.ip_p;
    ipPseh.tcpLen = sizeof(struct tcphdr) + blockStrLen;

    tcpPseh.source_port = ntohs(tcpFinPacket.pk.tcph.th_sport);
    tcpPseh.dest_port = ntohs(tcpFinPacket.pk.tcph.th_dport);
    tcpPseh.sequence_number = ntohl(tcpFinPacket.pk.tcph.th_seq);
    tcpPseh.ack_number = ntohl(tcpFinPacket.pk.tcph.th_ack);
    tcpPseh.data_offset_reserved_flags = (tcpFinPacket.pk.tcph.th_off << 12) + tcpFinPacket.pk.tcph.th_flags;
    printf("%X\n",tcpPseh.data_offset_reserved_flags);

    tcpPseh.window_size = ntohs(tcpFinPacket.pk.tcph.th_win);
    tcpFinPacket.pk.tcph.th_sum = calcTcpChksum(&ipPseh, &tcpPseh, (uint8_t*)blockStr, blockStrLen);
    memcpy(&tcpFinPacket.blockStr, blockStr, blockStrLen);

    if (pcap_sendpacket(pcapH, (unsigned char*)&tcpFinPacket, sizeof(tcpPacket)+blockStrLen) != 0){
        printf("%s\n", pcap_geterr(pcapH));
    }
}
