#include <stdint.h>

typedef struct {
    char *dev;
    uint8_t myMac[6];
    uint8_t myIp[4];
}args_arpScan;
