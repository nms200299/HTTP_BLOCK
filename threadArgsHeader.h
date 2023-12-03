#include <stdint.h>

typedef struct {
    char *dev;
    uint8_t myMac[6];
    uint8_t myIp[4];
    uint8_t gatewayIp;
}args_arpScan;

typedef struct {
    char *dev;
    uint8_t myMac[6];
    uint8_t myIp[4];
    uint8_t gatewayIp;
    uint8_t (*ipTable)[256][6];
}args_arpSpoof;
