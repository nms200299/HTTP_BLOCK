#include <protocolHeader.h>
#include <pcap.h>
#include <string.h> // memcpy
#include <stdlib.h> // exit

void sendRelay(pcap_t* pcapH, u_char *packet, bpf_u_int32 caplen, uint8_t (*myMac)[6], uint8_t (*gwMac)[6]){
    etherHeader ethh;
    memcpy(ethh.shost, myMac, 6);
    memcpy(ethh.dhost, gwMac, 6);
    ethh.type = htons(0x0800);

    memcpy(packet, &ethh, sizeof(ethh));

    if (pcap_sendpacket(pcapH, (unsigned char*)packet, caplen) != 0){
        printf("%s\n", pcap_geterr(pcapH));
    }
}
