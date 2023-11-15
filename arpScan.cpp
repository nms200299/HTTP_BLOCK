#include <protocolHeader.h>
#include <threadArgsHeader.h>

#include <pcap.h>   // pcap
#include <stdlib.h> // exit
#include <string.h> // memcpy
#include <unistd.h> // usleep

void *arpScan(void *args){
    args_arpScan *arg = (args_arpScan*)args;

    char *dev = arg->dev;
    uint8_t myMac[6];
    uint8_t myIp[4];

    memcpy(myIp, arg->myIp,sizeof(arg->myIp));
    memcpy(myMac, arg->myMac, sizeof(arg->myMac));

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcapH = pcap_open_live(dev , BUFSIZ, 1, 1000, errbuf);
    if (pcapH == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", (char *)dev, errbuf);
        exit(0);
    }
    struct arpPacket arp_packet;

    memcpy(arp_packet.ether.shost, &myMac, 6);
    memcpy(arp_packet.arp.sha, &myMac, 6);
    memcpy(arp_packet.arp.sip, &myIp, 4);

    while(1){
        for (int loop=1; loop <=3; loop++){
            for(int targetIp=1; targetIp<=254; targetIp++) {
                memcpy(arp_packet.arp.dip, &myIp, 3);
                arp_packet.arp.dip[3] = targetIp;
                if (pcap_sendpacket(pcapH, (unsigned char*)&arp_packet, sizeof(arp_packet)) != 0){
                    printf("Fail sendpacket 1\n");
                    exit (-1);
                }
                usleep(1000);
            }
        }
        sleep(10);
    }

    pcap_close(pcapH);
    printf("Thread 2 Die!!\n");
}
