//It is built on a Big Endian system

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/types.h>

#include <linux/udp.h>
#include <linux/ip.h>
#include <net/protocol.h>
#include <linux/if_ether.h>
#include <linux/net.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <net/ip.h>
#include <linux/netdevice.h>  
#include <linux/netfilter_ipv4.h>

#include <linux/sched.h>
#include "mydrv.h"



static struct nf_hook_ops nfho;
struct udphdr *udp_header;          //udp header struct (not used)
struct iphdr *ip_header;          //ip header struct
unsigned char *payload;    // The pointer for the tcp payload.
char sourceAddr[20];
char myAddr[20] = "192.168.1.10"; 
char destAddr[20];

int packettoread = 0;
bool recorded = false;

unsigned int my_func(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{   

    //return NF_QUEUE;
    //printk("%d\n", recorded);
    if (recorded){
        return NF_ACCEPT;
    }

    register struct iphdr *iph;
    register struct tcphdr *tcph;
    struct tls_hdr *tlsh;
    struct handshake *handshake_h;


    // check if it is TCP package here
    if(skb == 0)
        return NF_ACCEPT;
    
    iph = ip_hdr(skb);
    if(iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;

    tcph = tcp_hdr(skb);
    sprintf(sourceAddr, "%u.%u.%u.%u", NIPQUAD(iph->saddr));
    

    if(packettoread > 0){
        if(strcmp(sourceAddr, myAddr) == 0){
            packettoread = packettoread - 1;
            if (packettoread <= 0){
                recorded = true;
            }
            printk("Packets to read: %d\n", packettoread);
            return NF_QUEUE; 
        }else{
            return NF_ACCEPT;
        }    
    }
    
    


    
    //sprintf(myAddr, "192.168.10.154");
    
    //printk("a lot of!\n");
    //we will dump all tls packet from a specific website
    if(!(strcmp(sourceAddr, myAddr))){
        printk("a packet\n");
        if (ntohs(tcph->source) == 443){
        
        //payload = (char *)((unsigned char *)tcph + (tcph->doff));
        payload = (void *)skb->data+tcph->doff*4+iph->ihl*4;

            if(payload[0] == TLS_HANDSHAKE && payload[1] == 3 && payload[2] == 3){
                tlsh = (struct tls_hdr*)(payload);

                printk("This is Handshake!\n");
                packettoread = 2;
                //recorded = true;
                return NF_QUEUE;


                //try to remove some bug
                if (tlsh->total_len[0] * 256 + tlsh->total_len[1] < 33){
                    return NF_ACCEPT;
                }

                //payload = payload + sizeof(struct tls_hdr);
                //handshake_h = (struct handshake *) payload;
                //if (handshake_h->handshake_type == SERVER_HELLO){
                u_char tmp_type = (u_char *) (payload + sizeof(struct tls_hdr)) ;
                if (tmp_type == SERVER_HELLO){
                    printk("It is a server hello!\n");
                    recorded = true;
                    return NF_QUEUE;
                
                    // if(u_cipher == TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256){
                    //     printk("It is TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256!\n");
                    //     //packettoread = 1;
                    //     recorded = true;
                    //     return NF_QUEUE;
                    // }
                    // else{
                    //     printk("Incorrect version: %s\n", u_cipher);
                    //     return NF_ACCEPT;
                    // }
                }
                    
            }
        }
    }
        

        //printk("length %d\n", tlsh->total_len[0]*256 + tlsh->total_len[1]);
        //printk("length %d\n", ntohs(tlsh->total_len));
        //     printk("IP:[%u.%u.%u.%u]-->[%u.%u.%u.%u];\n",NIPQUAD(iph->saddr), NIPQUAD(iph->daddr));
        //     printk("tot_len: %d\n", ntohs(iph->tot_len));

        //printk("IP:[%u.%u.%u.%u]-->[%u.%u.%u.%u];\n",NIPQUAD(iph->saddr), NIPQUAD(iph->daddr));
        //printk("tot_len: %d\n", ntohs(iph->tot_len));        
        //printk("IP (version %u, ihl %u, tos 0x%x, ttl %u, id %u, length %u, ",
        //                                iph->version, iph->ihl, iph->tos, iph->ttl,
        //                                ntohs(iph->id), ntohs(iph->tot_len));
	    //tcph = (struct tcphdr *)skb->data + iph->ihl*4;
        //printk("TCP: [%u]-->[%u];\n", ntohs(tcph->source), ntohs(tcph->dest));
	    
        //printk("tcph->dest = %d\n", ntohs(tcph->dest));
	    //printk("tcph->source = %d\n", ntohs(tcph->source));
        //printk("*********************************************\n");

    return NF_ACCEPT;

}


static __init int mydrv_init(void)
{
    //printk("helloworld!\n");
    nfho.hook = my_func;
    nfho.pf = NFPROTO_IPV4;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.priority = NF_IP_PRI_FIRST;
    int ret = 0;
    struct net *n;
    for_each_net(n)
        ret += nf_register_net_hook(n, &nfho);
   printk("kernel module mydrv start!\n");
   printk("nf_register_hook returnd %d\n", ret);
   return 0;
}
 
static __exit void mydrv_exit(void)
{
struct net *n;
    for_each_net(n)
        nf_unregister_net_hook(n, &nfho);
        printk("kernel module mydrv exit!\n");
}
 
module_init(mydrv_init);
module_exit(mydrv_exit);
 
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Stone");
