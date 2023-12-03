#include <protocolHeader.h>
#include <pcap.h>
#include <stdlib.h> // exit
#include <string.h> // memcpy

void sendArpReq(pcap_t* pcapH, uint8_t (*myMac)[6], uint8_t (*myIp)[4], uint8_t targetIp){
    struct arpPacket arp_packet;

    memcpy(arp_packet.ether.shost, myMac, 6);
    memcpy(arp_packet.arp.sha, myMac, 6);
    memcpy(arp_packet.arp.sip, myIp, 4);
    memcpy(arp_packet.arp.dip, myIp, 3);
    arp_packet.arp.dip[3] = targetIp;

    if (pcap_sendpacket(pcapH, (unsigned char*)&arp_packet, sizeof(arp_packet)) != 0){
        printf("Fail sendpacket 1\n");
        exit (-1);
    }

}
