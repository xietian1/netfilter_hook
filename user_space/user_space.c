#include <stdio.h>
#include <assert.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
        struct nfq_data *nfa, void *data)
{
    u_int32_t id = 0;
    struct nfqnl_msg_packet_hdr *ph;

    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
    }

    printf("packet: %u\n", id);
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int    fd;
    int rv;
    char buf[4096];

    assert((h = nfq_open()) != NULL);
    assert(nfq_unbind_pf(h, AF_INET) == 0);
    assert(nfq_bind_pf(h, AF_INET) == 0);

    assert((qh = nfq_create_queue(h, 80, &cb, NULL)) != NULL);
    assert(nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) == 0);

    fd = nfq_fd(h);

    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        nfq_handle_packet(h, buf, rv);
    }

    nfq_destroy_queue(qh);

    nfq_close(h);
    return 0;
}