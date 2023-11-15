#include <protocolHeader.h>
#include <stdint.h>
#include <stdio.h>
#include <pcap.h>

uint8_t recvDhcp(const u_char* packet){
    dhcpHeader *dhcph = (dhcpHeader *)packet;

    if (dhcph->op == (uint8_t)0x01){
        // DHCP REQ 패킷이면
        printf("---------------------------------------------------------\n");
        printf("Device is Connected!\n");
        printf("Device MAC is ");
        printf("%02X:", dhcph->chaddr[0]);
        printf("%02X:", dhcph->chaddr[1]);
        printf("%02X:", dhcph->chaddr[2]);
        printf("%02X:", dhcph->chaddr[3]);
        printf("%02X:", dhcph->chaddr[4]);
        printf("%02X\n", dhcph->chaddr[5]);
        printf("Device IP is ");
        for (int srch=0; srch <= 307; srch++){
            if (dhcph->options[srch] == (uint8_t)0x32){
                printf("%d.", dhcph->options[srch+2]);
                printf("%d.", dhcph->options[srch+3]);
                printf("%d.", dhcph->options[srch+4]);
                printf("%d\n", dhcph->options[srch+5]);
                break;
            } else {
                srch = srch+1 + dhcph->options[srch+1];
            }
        }
        printf("\n");

        return 1;
    } else {
        return 0;
    }
}
