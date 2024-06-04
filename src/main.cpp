#include <stdio.h>
#include <stdint.h>
#include <pthread.h>    // thread
#include <string.h>     // memcpy
#include <pcap.h>       // pcap
#include <unistd.h>     // usleep
#include <stdlib.h>     // exit, system
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
    char* blockDomain[]= {
        "test.gilgil.net",
        "joongbu.ac.kr"
    };

    char blockAlertStr[]= {
        "<h1>This page is blocked by HTTP_BLOCK ! </h1>\x0d\x0a"
    };

    char *dev = argv[1];
    char command[100];
    snprintf(command, sizeof(command), "ifconfig %s mtu 9000", argv[1]);
    system(command);

    uint8_t gatewayIp;
    printf("Gateway IP :");
    scanf("%d", &gatewayIp);
    // get Gateway Ip

    uint8_t myMac[6];
    uint8_t myIp[4];
    myinfo(myMac, myIp);
    // get My Ip, Mac

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev , BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
        return -1;
    }
    sendArpReq(pcap, &myMac, &myIp, gatewayIp);
    // get Gateway Mac

    pthread_t thread_arpScan;
    args_arpScan arg_arpScan;
    arg_arpScan.dev = dev;

    memcpy(arg_arpScan.myIp, myIp, sizeof(arg_arpScan.myIp));
    memcpy(arg_arpScan.myMac, myMac, sizeof(arg_arpScan.myMac));
    arg_arpScan.gatewayIp = gatewayIp;
    pthread_create(&thread_arpScan, 0, arpScan, (void *)&arg_arpScan);
    // ARP Scan Thread Create

    pthread_t thread_arpSpoof;
    args_arpSpoof arg_arpSpoof;
    arg_arpSpoof.dev = dev;
    memcpy(arg_arpSpoof.myIp, myIp, sizeof(arg_arpSpoof.myIp));
    memcpy(arg_arpSpoof.myMac, myMac, sizeof(arg_arpSpoof.myMac));
    arg_arpSpoof.gatewayIp = gatewayIp;
    arg_arpSpoof.ipTable = &ipTable;
    pthread_create(&thread_arpSpoof, 0, arpSpoof, (void *)&arg_arpSpoof);
    // ARP Spoofing Thread Create

    while(1){
        struct pcap_pkthdr* header;
        const u_char* packet;

        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        u_char* orgPacket=(u_char*)packet;
        struct etherHeader *ethh = (struct etherHeader *)packet;
        uint16_t packetType_3L = htons(ethh->type);
        packet += sizeof(etherHeader);

        switch (packetType_3L){
            case ETHERTYPE_ARP:
                recvArpRep(packet, ipTable);
                break;
            case ETHERTYPE_IP:
                uint8_t blockFlag=0;
                struct ip *iph;
                iph = (struct ip *)packet;
                // IP 패킷이면 IP 헤더를 구한다.
//                printf("IP Size : %02X %02X \n", *((uint8_t*)iph), *((uint8_t*)iph+1));
//                printf("Org CheckSum : %04X \n", htons(iph->ip_sum));
//                printf("Calc CheckSum : %04X \n", calcIpChksum(iph));


                packet += iph->ip_hl*4;
                uint16_t packetType_4L = iph->ip_p;



                switch (packetType_4L){
                    case IPPROTO_UDP:
                        packet += sizeof(struct udphdr);
                        recvDhcp(packet);
                        break;
                    case IPPROTO_TCP:
                        blockFlag = recvTcp(packet, blockDomain);
                        break;
                }

                if (blockFlag) {
                // 패킷 차단
                        sendTcpClose(pcap, orgPacket, (char *)&blockAlertStr);
                } else {
                // 패킷 릴레이
                    if (memcmp(ethh->shost, ipTable[gatewayIp], 6) != 0){
                        // eth->srcMAC != gwMac
                        sendRelay(pcap, orgPacket, header->caplen, &myMac, &(ipTable[gatewayIp]));
                        // send to gw
                    } else {
                        sendRelay(pcap, orgPacket, header->caplen, &myMac, &(ipTable[*(((uint8_t*)&(iph->ip_dst))+3)]));
                        // send to ipv4->dstIp
                    }
                }

            break;
        }
    }
}
