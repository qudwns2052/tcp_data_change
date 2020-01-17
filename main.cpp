#include "include.h"

static char ** global_argv = nullptr;
static unsigned char global_packet[10000];
static int global_ret = 0;
static map<Key, pair<uint32_t, uint32_t>> session;


/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph)
    {
        id = ntohl(ph->packet_id);
    }
    ret = nfq_get_payload(tb, &data);


    //*****************************************************************//

    struct iphdr * ip_header = reinterpret_cast<struct iphdr*>(data);
    struct tcphdr * tcp_header = reinterpret_cast<struct tcphdr*>(data + ip_header->ihl*4);
    uint8_t * payload = data + (ip_header->ihl*4) + (tcp_header->th_off*4);

    char *Pattern = global_argv[1];
    char *Replace = global_argv[2];

    uint32_t Pattern_len = strlen(Pattern);
    uint32_t Replace_len = strlen(Replace);
    int gap_len = Replace_len - Pattern_len;
    uint8_t temp_buf[1500];


    Key key;
    uint32_t state;

    if(ip_header->saddr < ip_header->daddr)
    {
        key = Key(ip_header->saddr, ip_header->daddr,
                       tcp_header->th_sport, tcp_header->th_dport);
        state = 0;
    }
    else
    {
        key = Key(ip_header->daddr, ip_header->saddr,
                       tcp_header->th_dport, tcp_header->th_sport);
        state = 1;
    }

    if(session.find(key) == session.end())
    {
        session[key].first = 0;
        session[key].second = state;
    }

    if(session[key].second == state)
    {
        if(gap_len < 0)
        {
            tcp_header->seq -= htonl(-session[key].first);
        }
        else
        {
            tcp_header->seq += htonl(session[key].first);
        }
    }
    else
    {
        if(gap_len < 0)
        {
            tcp_header->ack_seq += htonl(-session[key].first);
        }
        else
        {
            tcp_header->ack_seq -= htonl(session[key].first);
        }

    }


    int i = 0;

    while(i < ret - (Pattern_len - 1))
    {
        if(!memcmp(payload + i, Pattern, Pattern_len))
        {
            memset(temp_buf, 0, 1500);
            memcpy(temp_buf, payload + i + Pattern_len, ret - (i + Pattern_len));
            memcpy(payload + i, Replace, Replace_len);
            memcpy(payload + i + Replace_len, temp_buf, ret - (i + Replace_len));

            session[key].first += gap_len;

            if(gap_len < 0)
            {
                ip_header->tot_len -= htons(-gap_len);
            }
            else
            {
                ip_header->tot_len += htons(gap_len);
            }

            ret += gap_len;
            i+= Replace_len;

            session[key].second = state;

        }
        else
        {
            i++;
        }
    }



    memset(global_packet, 0, 10000);
    memcpy(global_packet, data, ret);
    global_ret = ret;

    cal_checksum_ip(global_packet);
    cal_checksum_tcp(global_packet);


    key.print_Key();
    printf("------------------------------------------------------------\n");


    //*****************************************************************//




    return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(nfa);
//    printf("entering callback\n");
    return nfq_set_verdict(qh, id, NF_ACCEPT, global_ret, global_packet);
}

int main(int argc, char **argv)
{
    //**************************************

    global_argv = argv;

    //**************************************



    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
//            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}
