#include <protocolHeader.h>
#include <threadArgsHeader.h>
#include <srcLinkHeader.h>
#include <pcap.h>   // pcap
#include <stdlib.h> // exit
#include <unistd.h> // usleep

void *arpScan(void *args){
    args_arpScan *arg = (args_arpScan*)args;
    char *dev = arg->dev;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcapH = pcap_open_live(dev , BUFSIZ, 1, 1000, errbuf);
    if (pcapH == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", (char *)dev, errbuf);
        exit(0);
    }

    while(1){
        for(int targetIp=1; targetIp<=254; targetIp++) {
            if (targetIp != arg->gatewayIp) {
                sendArpReq(pcapH, &(arg->myMac), &(arg->myIp), targetIp);
                usleep(1000);
            }
        }
        sleep(10);
    }

    pcap_close(pcapH);
    printf("Thread 2 Die!!\n");
}
