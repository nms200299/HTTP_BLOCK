#include <protocolHeader.h>
#include <pcap.h>
#include <string.h>
#define TLS_CLIENT_HELLO 0x01
#define TLS_SERVER_NAME 0x00

uint8_t recvTls(const u_char *packet, char *blockDomain[]){
    tlsClientHelloHeader *tlsH=(tlsClientHelloHeader*)packet;
    if (tlsH->handshakeType == TLS_CLIENT_HELLO) {
        packet = packet+sizeof(tlsClientHelloHeader);
        // TLS - Random 필드까지 뛰어넘음.

        uint8_t sidLen = (uint8_t)*packet;
        packet = packet+sidLen+sizeof(sidLen);
        // TLS - Session ID 필드까지 뛰어넘음.

        uint16_t cipSuitLen = ntohs(*((uint16_t *)packet));
        packet = packet+cipSuitLen+sizeof(cipSuitLen);
        // TLS - Cipher Suites 필드까지 뛰어넘음.

        uint8_t compMethodLen = *packet;
        packet = packet+compMethodLen+sizeof(compMethodLen);
        // TLS - CompressionMethods 필드까지 뛰어넘음.

        uint16_t extTotalLen = ntohs(*((uint16_t *)packet));
        packet = packet+sizeof(extTotalLen);
        // TLS - Extensions Length 필드까지 뛰어넘음.


        uint16_t extLoop=0;
        while (extLoop <= extTotalLen){
            uint16_t extType = ntohs(*((uint16_t *)packet));
            packet = packet+sizeof(extType);
            uint16_t extLen = ntohs(*((uint16_t *)packet));
            packet = packet+sizeof(extLen);

            if (extType == TLS_SERVER_NAME){
                packet = packet+3; // Server Name List (2byte) + Server Name Type (1byte)
                uint16_t serverNameLen = ntohs(*((uint16_t *)packet));
                packet = packet+sizeof(serverNameLen);
                char domain[256];
                memset(&domain,0x00,256);
                for (uint16_t serverNameLoop=0; serverNameLoop < serverNameLen; serverNameLoop++){
                    domain[serverNameLoop] = *(packet+serverNameLoop);
                }
                for (uint8_t diffLoop=0; diffLoop <= 9; diffLoop++){
                    if (blockDomain[diffLoop] != NULL){
                        if (strcasestr((const char *)&domain, (const char *)(blockDomain[diffLoop])) != NULL){
                            printf("HTTPS TLS SNI : %s \n", domain);
                            return 1;
                        }
                    } else {
                        break;
                    }
                }
                break;
            } else {
                packet = packet+extLen;
                extLoop = sizeof(extType)+sizeof(extLen)+extLen;
            }
        }
    }
    return 0;
}
