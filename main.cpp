#include <stdio.h>
#include <stdint.h>
#include <pthread.h>    // thread
#include <string.h>     // memcpy
#include <pcap.h>       // pcap
#include <unistd.h>     // usleep
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
// OS 제공 헤더

#include <protocolHeader.h>
#include <srcLinkHeader.h>
#include <threadArgsHeader.h>
// 사용자 정의 헤더

uint8_t ipTable[256][6];

void usage() {
    printf("syntax: ./HTTP_BLOCK <interface>\n");
    printf("sample: ./HTTP_BLOCK ens33\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return 0;
    }
    char *dev = argv[1];

    uint8_t myMac[6];
    uint8_t myIp[4];
    myinfo(myMac, myIp);

    pthread_t thread_arpScan;
    args_arpScan arg_arpScan;
    arg_arpScan.dev = dev;
    memcpy(arg_arpScan.myIp, myIp, sizeof(arg_arpScan.myIp));
    memcpy(arg_arpScan.myMac, myMac, sizeof(arg_arpScan.myMac));
    pthread_create(&thread_arpScan, 0, arpScan, (void *)&arg_arpScan);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev , BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
        return -1;
    }

    while(1){
        struct pcap_pkthdr* header;
        const u_char* packet;

        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        struct etherHeader *ethh = (struct etherHeader *)packet;
        uint16_t packetType_3L = htons(ethh->type);
        packet += sizeof(etherHeader);

        switch (packetType_3L){
        case ETHERTYPE_ARP:
            recvArpRep(packet, ipTable);
            break;
        case ETHERTYPE_IP:

            struct ip *iph = (struct ip *)packet;
            packet += sizeof(struct ip);
            uint16_t packetType_4L = iph->ip_p;

            switch (packetType_4L){
            case IPPROTO_UDP:
                packet += sizeof(struct udphdr);
                recvDhcp(packet);
                break;
            }
            break;
        }
    }
}
