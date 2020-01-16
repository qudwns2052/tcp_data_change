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

//    dump(data, ntohs(ip_header->tot_len));
//    cout << endl;
//    printf("ip_header_checksum = %04X , %04X\n", ip_header->check, cal_checksum_ip(data));
//    printf("tcp_header_checksum = %04X , %04X\n", tcp_header->check, cal_checksum_tcp(data));
//    printf("tcp_header_hlen = %u\n", tcp_header->th_off*4);

//    dump(data, ntohs(ip_header->tot_len));

    char *Pattern = global_argv[1];
    char *Replace = global_argv[2];

    uint32_t Pattern_len = strlen(Pattern);
    uint32_t Replace_len = strlen(Replace);
    int gap_len = Replace_len - Pattern_len;
    uint8_t temp_buf[1500];


    Key key;
    uint32_t state;

    if(ntohl(ip_header->saddr) < ntohl(ip_header->daddr))
    {
        key = Key(ntohl(ip_header->saddr), ntohl(ip_header->daddr),
                       ntohs(tcp_header->th_sport), ntohs(tcp_header->th_dport));
        state = 0;
    }
    else
    {
        key = Key(ntohl(ip_header->daddr), ntohl(ip_header->saddr),
                       ntohs(tcp_header->th_dport), ntohs(tcp_header->th_sport));
        state = 1;
    }

    if(session.find(key) == session.end())
    {
        printf("make\n");
        session[key].first = 0;
        session[key].second = state;
    }

    if(session[key].second == state)
    {

        printf("same state\n");
        printf("before tcp_header->seq = %08X\n", ntohl(tcp_header->seq));
        printf("session[key].first = %d\n", session[key].first);

        if(gap_len < 0)
        {
            tcp_header->seq -= htonl(-session[key].first);
        }
        else
        {
            tcp_header->seq += htonl(session[key].first);
        }
        printf("after tcp_header->seq = %08X\n", ntohl(tcp_header->seq));
    }
    else
    {
        printf("diff state\n");
        printf("before tcp_header->ack_seq = %08X\n", ntohl(tcp_header->ack_seq));
        printf("session[key].first = %d\n", session[key].first);

        if(gap_len < 0)
        {
            tcp_header->ack_seq += htonl(-session[key].first);
        }
        else
        {
            tcp_header->ack_seq -= htonl(session[key].first);
        }

        printf("after tcp_header->ack_seq = %08X\n", ntohl(tcp_header->ack_seq));
    }


    int i = 0;

    while(i < ret - (Pattern_len - 1))
    {
        if(!memcmp(payload + i, Pattern, Pattern_len))
        {
            memset(temp_buf, 0, sizeof(char) * 1500);
            memcpy(temp_buf, payload + i + Pattern_len, ret - (i + Pattern_len));
            memcpy(payload + i, Replace, Replace_len);
            memcpy(payload + i + Replace_len, temp_buf, ret - (i + Replace_len));


            session[key].first += gap_len;
            printf("session[key] = %d\n", session[key]);
//            printf("else = %d\n", ret - (i + Pattern_len));
//            printf("ret = %d\n", ret);
//            printf("value = %d\n", session[key]);
//            printf("gap_len = %d\n", gap_len);
//            printf("ip_header->tot_len = %04X\n", ntohs(ip_header->tot_len));



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
        }
        else
        {
            i++;
        }
    }



    printf("seq = %08X\nack = %08X\n", ntohl(tcp_header->seq), ntohl(tcp_header->ack_seq));
    printf("ret = %08X\n", ret);

    session[key].second = state;
    key.print_Key();
    memcpy(global_packet, data, ret);
    global_ret = ret;

    cal_checksum_ip(global_packet);
    cal_checksum_tcp(global_packet);

    printf("------------------------------------------------------------\n");

//    dump(global_packet, ntohs(ip_header->tot_len));

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