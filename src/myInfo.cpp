#include <stdint.h>
#include <stdio.h>
#include <stdlib.h> // exit

void myinfo(uint8_t myMac[6], uint8_t myIp[4]){
    FILE *fp;
    char buffer[80];
    fp = popen("ifconfig | grep -o -E '([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})'", "r");
    if (fp == NULL) {
        perror("popen");
        exit(1);
    }
    if (fgets(buffer, sizeof(buffer), fp) != NULL) {
        sscanf(buffer, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &myMac[0], &myMac[1], &myMac[2], &myMac[3], &myMac[4], &myMac[5]);
    }
    pclose(fp);

    fp = popen("hostname -I", "r");
    if (fp == NULL) {
        perror("popen");
        exit(1);
    }
    if (fgets(buffer, sizeof(buffer), fp) != NULL) {
        sscanf(buffer, "%hhu.%hhu.%hhu.%hhu", &myIp[0], &myIp[1], &myIp[2], &myIp[3]);
    }
    pclose(fp);
}
