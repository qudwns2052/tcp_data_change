#pragma once
#include "include.h"

class Key
{
public:
    uint32_t saddr;
    uint32_t daddr;
    uint32_t ports;

    Key() {}
    Key(uint32_t _saddr, uint32_t _daddr, uint16_t _sport, uint16_t _dport) : saddr(_saddr), daddr(_daddr)
    {
        ports = _sport;
        ports = (ports << 16) + _dport;
    }

    bool operator < (const Key & ref) const
    {
        if(saddr == ref.saddr)
        {
            if(daddr == ref.daddr)
            {
                return ports < ref.ports;
            }
            else
            {
                return daddr < ref.daddr;
            }
        }
        else
        {
            return saddr < ref.saddr;
        }
    }

    void print_Key(void)
    {
        print_ip(saddr); print_ip(daddr);
        printf("%u\t%u\n", (ports >> 16) & 0xffff, ports & 0xffff);


    }

};
