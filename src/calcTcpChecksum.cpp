#include <protocolHeader.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <stdio.h>

unsigned short CheckSum(unsigned short *buffer, int size){
    unsigned long long int cksum=0;
    while(size > 1)
    {
        unsigned short data = ntohs(*buffer);
        cksum += data;
        //printf("%x\n", data);
        buffer++;
        size -=sizeof(unsigned short);
    }
    if(size)
        cksum += *(unsigned short*)buffer;
    cksum = (cksum >> 16) + (cksum & 0xffff);
    return (unsigned short)(cksum);
}


uint16_t calcTcpChksum(ipPseudoHeader *iph, tcpPseudoHeader *tcph, uint8_t *data, int dataLen) {
    unsigned long long int chksum=0;
    chksum = CheckSum((unsigned short *)iph, sizeof(ipPseudoHeader));;

    unsigned long long int sum_chksum=0;
    sum_chksum += iph->sIp >> 16;
    sum_chksum += iph->sIp << 16 >> 16;
    sum_chksum += iph->dIp >> 16;
    sum_chksum += iph->dIp << 16 >> 16;
    sum_chksum += iph->protocol;
    sum_chksum += sizeof (struct tcphdr) + dataLen;
    sum_chksum = (sum_chksum >> 16) + (sum_chksum & 0xffff);
    sum_chksum += tcph->source_port;
    sum_chksum += tcph->dest_port;
    sum_chksum += tcph->sequence_number >> 16;
    sum_chksum += tcph->sequence_number << 16 >> 16;
    sum_chksum += tcph->ack_number >> 16;
    sum_chksum += tcph->ack_number << 16 >> 16;
    sum_chksum += tcph->data_offset_reserved_flags;
    sum_chksum += tcph->window_size;
    sum_chksum += CheckSum((unsigned short *)data, dataLen);
    sum_chksum = (sum_chksum >> 16) + (sum_chksum & 0xffff);

    return htons((uint16_t)(sum_chksum ^ 0xffff));
}
