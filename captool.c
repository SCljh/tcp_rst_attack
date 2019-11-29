//
// Created by root on 2019/11/29.
//

#include "captool.h"
#include "attack_tool.h"
#include "libnetool.h"

int selfFiltter(u_short *packet)
{
    //add some code what you want
    return 1;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct sniff_ip *ip; /* The IP header */
    const struct sniff_tcp *tcp; /* The TCP header */
    const char *payload; /* Packet payload */

    struct ip_data *ip_d;
    struct tcp_data *tcp_d;
    struct ethernet_data *ether_d;

    u_int size_ip;
    u_int size_tcp;

    ip_d = (struct ip_data*)malloc(sizeof(struct ip_data));
    tcp_d = (struct tcp_data*)malloc(sizeof(struct tcp_data));
    ether_d = (struct ethernet_data*)malloc(sizeof(struct ethernet_data));

    ethernet = (struct sniff_ethernet*)(packet);
    for (int i = 0; i < ETHER_ADDR_LEN; i++){
        ether_d->mac_src[i] = ethernet->ether_shost[i];
        ether_d->mac_dst[i] = ethernet->ether_dhost[i];
    }

#ifdef DEBUG
    //printf("ethernet src:%x");
    //printf("ethernet dst:%x");
#endif

    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }
    ip_d->ip_src = ip->ip_dst;
    ip_d->ip_dst = ip->ip_src;

#ifdef DEBUG
    printf("src ip:%s\n", inet_ntoa(ip->ip_src));
    printf("des ip:%s\n", inet_ntoa(ip->ip_dst));
#endif

    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    if (!selfFiltter((u_short*)tcp)){
        return;
    }
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }

    tcp_d->port_src = tcp->th_dport;
    tcp_d->port_dst = tcp->th_sport;
    tcp_d->seq = ntohl(tcp->th_ack);
    tcp_d->win = ntohs(tcp->th_win);

#ifdef DEBUG
    printf("src port:%d\n"
           "des port:%d\n",  ntohs(tcp->th_sport), ntohs(tcp->th_dport));
    printf("tcp seq:%u\n", ntohl(tcp->th_seq));
    printf("tcp ack:%u\n", ntohl(tcp->th_ack));
    printf("tcp window:%hu\n", ntohs(tcp->th_win));
    printf("tcp seq should be (%u)\n", ntohl(tcp->th_ack));
#endif

    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    printf("payload:%s\n", payload);
    buildRstPacket(ip_d, tcp_d);

}
