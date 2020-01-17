#include "include.h"

void dump(unsigned char* buf, int size)
{
    int i;
    for (i = 0; i < size; i++) {
        if (i % 16 == 0)
            printf("\n");
        printf("%02x ", buf[i]);
    }
}


uint16_t calc(uint16_t * data, uint32_t data_len)
{
    uint32_t temp_checksum = 0;
    uint16_t checksum;

    uint32_t cnt, state;

    if(data_len % 2 == 0)
    {
        cnt = data_len / 2;
        state = 0;
    }
    else {
        cnt = (data_len / 2) + 1;
        state = 1;
    }


    for(int i = 0; i < cnt; i++)
    {
        if((i + 1) == cnt && state == 1)
            temp_checksum += ntohs((data[i] & 0x00ff));
        else
            temp_checksum += ntohs(data[i]);

    }

    temp_checksum = ((temp_checksum >> 16) & 0xffff) + temp_checksum & 0xffff;
    temp_checksum = ((temp_checksum >> 16) & 0xffff) + temp_checksum & 0xffff;

    checksum = temp_checksum;

    return checksum;
}

uint16_t cal_checksum_ip(uint8_t * data)
{
    struct iphdr * ip_header = reinterpret_cast<struct iphdr*>(data);
    uint16_t checksum;

    ip_header->check = 0;
    checksum = calc(reinterpret_cast<uint16_t *>(ip_header), (ip_header->ihl*4));

    ip_header->check = htons(checksum ^ 0xffff);

    return ip_header->check;
}

uint16_t cal_checksum_tcp(uint8_t * data)
{
    struct iphdr * ip_header = reinterpret_cast<struct iphdr*>(data);
    struct tcphdr * tcp_header = reinterpret_cast<struct tcphdr*>(data + ip_header->ihl*4);

    struct pseudohdr pseudo_header;

    memcpy(&pseudo_header.saddr, &ip_header->saddr, sizeof(uint32_t));
    memcpy(&pseudo_header.daddr, &ip_header->daddr, sizeof(uint32_t));
    pseudo_header.reserved = 0;
    pseudo_header.protocol = ip_header->protocol;
    pseudo_header.tcp_len = htons(ntohs(ip_header->tot_len) - (ip_header->ihl*4));

    uint16_t temp_checksum_pseudo, temp_checksum_tcp, checksum;
    uint32_t temp_checksum;

    tcp_header->check = 0;

    temp_checksum_pseudo = calc(reinterpret_cast<uint16_t *>(&pseudo_header), sizeof(pseudo_header));
    temp_checksum_tcp = calc(reinterpret_cast<uint16_t *>(tcp_header), ntohs(pseudo_header.tcp_len));

    temp_checksum = temp_checksum_pseudo + temp_checksum_tcp;

    temp_checksum = ((temp_checksum >> 16) & 0xffff) + temp_checksum & 0xffff;

    temp_checksum = ((temp_checksum >> 16) & 0xffff) + temp_checksum & 0xffff;

    checksum = temp_checksum;

    tcp_header->check = htons(checksum ^ 0xffff);

    return tcp_header->check;
}

