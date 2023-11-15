#include <protocolHeader.h>
#include <arpa/inet.h> // htons
#include <pcap.h> // pcap

void *recvArpRep(const u_char* packet, uint8_t ipTable[256][6]){
    struct arpHeader *arpPointer = (struct arpHeader *)packet;

    unsigned char *sha = arpPointer->sha;
    unsigned char *sip = arpPointer->sip;
    unsigned char *dha = arpPointer->dha;
    unsigned char *dip = arpPointer->dip;
    int opcode = htons(arpPointer->op);    //request: 1, reply: 2

    if(opcode == 2) {
        int cCls = sip[3];
        bool chkFlag=false;
        for (int loop=0; loop<=5; loop++){
            if (ipTable[cCls][loop] != 0) {
                chkFlag=true;
            }
        }

        if (chkFlag == false){
            printf("---------------------------------------------------------\n");
            printf("[ARP Packet : Reply]\n");
            printf("Source MAC Address : %02x:%02x:%02x:%02x:%02x:%02x\n",sha[0], sha[1], sha[2], sha[3], sha[4], sha[5]);
            printf("Source IP Address : %d.%d.%d.%d\n",sip[0], sip[1], sip[2], sip[3]);

            ipTable[cCls][0] = sha[0];
            ipTable[cCls][1] = sha[1];
            ipTable[cCls][2] = sha[2];
            ipTable[cCls][3] = sha[3];
            ipTable[cCls][4] = sha[4];
            ipTable[cCls][5] = sha[5];
            printf("ARP Table [%d] : %02x:%02x:%02x:%02x:%02x:%02x\n", cCls, ipTable[cCls][0], ipTable[cCls][1], ipTable[cCls][2], ipTable[cCls][3], ipTable[cCls][4], ipTable[cCls][5]);
        }
    }
}
