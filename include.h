#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <iostream>
#include <cstring>
#include <sys/ioctl.h>
#include <net/if.h>
#include <map>


#include <libnetfilter_queue/libnetfilter_queue.h>

#include "cal_checksum.h"
#include "protocol_structure.h"

using namespace std;



#define BUF_LEN 128
