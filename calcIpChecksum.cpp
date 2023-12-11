#include <protocolHeader.h>
#include <netinet/ip.h>

uint16_t  calcIpChksum(struct ip *iph){
    uint8_t ipLen = iph->ip_hl * 4;
    iph->ip_sum = 0x0000;

    uint32_t ipSum=0;
    for (uint8_t i=0; i<=(ipLen/2)-1; i++){
        ipSum += htons(((uint16_t *)iph)[i]);
    } // IP 헤더를 2byte씩 끊어서 각각 더한다.

    ipSum = (ipSum >> 16) + (ipSum & 0xFFFF);
    // 하위 16비트를 초과한 나머지 상위 16비트(캐리 비트) 값은 더해준다.
    // 하위 16비트 : (ipSum & 0xFFFF)
    //      0000 0000 0000 1010 0000 0000 0000 0101 AND
    //      0000 0000 0000 0000 1111 1111 1111 1111 =
    //      0000 0000 0000 0000 0000 0000 0000 0101
    // 상위 16비트 : (ipSum >> 16)
    //      0000 0000 0000 1010 0000 0000 0000 0101 SHIFT(RIGHT 16) =
    //      0000 0000 0000 0000 0000 0000 0000 1010

    ipSum = (uint16_t)~ipSum;
    // 1의 보수를 취한다. (비트 반전)
    return ipSum;

}
