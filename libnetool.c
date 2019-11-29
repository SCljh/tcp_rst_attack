//
// Created by root on 2019/11/29.
//

#include "libnetool.h"

int buildRstPacket(struct ip_data *ip, struct tcp_data *tcp)
{
    int c ;
    u_char *cp;
    libnet_t *l;
    libnet_ptag_t t;
    char *payload = "wdnmd";
    u_char HostAddr[255],MyAddr[255];
    u_short payload_s;
    u_long src_ip,dst_ip;
    u_short src_prt,dst_prt;
    char *src_char_ip, *dst_char_ip;

    char errbuf[LIBNET_ERRBUF_SIZE];

    l=libnet_init( LIBNET_RAW4,NULL,errbuf);
    if(l==NULL)
    {
        printf("libnet failed: %s",errbuf);
        exit(EXIT_FAILURE);
    }


    src_char_ip = inet_ntoa(ip->ip_src);
    dst_char_ip = inet_ntoa(ip->ip_dst);

    dst_prt = ntohs(tcp->port_dst);
    src_prt = ntohs(tcp->port_src);

    t=libnet_build_tcp_options("\003\003\012\001\002\004\001\011\010\012\077\077\077\077\000\000\000\000\000\000",20,l,0);
    if(t==-1)
    {printf("cant build TCP options: %s\n",libnet_geterror(l));
        goto bad;}

    payload_s = strlen(payload);

    t=libnet_build_tcp(src_prt,dst_prt,tcp->seq,0,TH_RST,tcp->win,0,10,
                       LIBNET_TCP_H+20+payload_s,(uint8_t *)payload,payload_s,l,0 );
    //t=libnet_build_tcp(src_port_test,dst_port_test,tcp->seq,0x02020202,TH_RST,tcp->win,0,10,
    //                   LIBNET_TCP_H + 20 + payload_s,(uint8_t *)payload,payload_s,l,0 );
    if(t==-1)
    {
        printf("cant build TCP header:%s\n",libnet_geterror(l));
        goto bad;
    }

    t=libnet_build_ipv4(LIBNET_IPV4_H+LIBNET_TCP_H+20+payload_s,0,242,0,64,IPPROTO_TCP,0, ip->ip_src.s_addr, ip->ip_dst.s_addr,NULL,0,l,0);

    if(t==-1)
    {
        printf("cant build IP header:%s\n",libnet_geterror(l));
        goto bad;
    }

    c=libnet_write(l);
    if(c==-1)
    {
        printf("write error:%s\n",libnet_geterror(l));
        goto bad;
    }
    else
    {
#ifdef DEBUG
        printf("--------packet info--------\n");
        printf("src ip:%s\n", src_char_ip);
        printf("dst ip:%s\n", dst_char_ip);
        printf("src port:%d\n"
               "des port:%d\n",  ntohs(tcp->port_src), ntohs(tcp->port_dst));
        printf("tcp seq:%u\n", tcp->seq);
        printf("tcp window:%hu\n", tcp->win);
#endif
        printf("wrote %d byte TCP packet\n",c);
    }
    libnet_destroy(l);
    return 1;

    bad:
    libnet_destroy(l);
    return 0;

}

int buildRstPacket_e(struct ip_data *ip, struct tcp_data *tcp, struct ethernet_data *ether)
{
    int c ;
    u_char *cp;
    libnet_t *l;
    libnet_ptag_t t;
    char *payload = "wdnmd";
    u_char HostAddr[255],MyAddr[255];
    u_short payload_s;
    u_long src_ip,dst_ip;
    u_short src_prt,dst_prt;
    char *src_char_ip, *dst_char_ip;

    char errbuf[LIBNET_ERRBUF_SIZE];

    l=libnet_init( LIBNET_RAW4,NULL,errbuf);
    if(l==NULL)
    {
        printf("libnet failed: %s",errbuf);
        exit(EXIT_FAILURE);
    }


    src_char_ip = inet_ntoa(ip->ip_src);
    dst_char_ip = inet_ntoa(ip->ip_dst);

    dst_prt = ntohs(tcp->port_dst);
    src_prt = ntohs(tcp->port_src);

    t=libnet_build_tcp_options("\003\003\012\001\002\004\001\011\010\012\077\077\077\077\000\000\000\000\000\000",20,l,0);
    if(t==-1)
    {printf("cant build TCP options: %s\n",libnet_geterror(l));
        goto bad;}

    payload_s = strlen(payload);

    t=libnet_build_tcp(src_prt,dst_prt,tcp->seq,0,TH_RST,tcp->win,0,10,
                       LIBNET_TCP_H+20+payload_s,(uint8_t *)payload,payload_s,l,0 );
    //t=libnet_build_tcp(src_port_test,dst_port_test,tcp->seq,0x02020202,TH_RST,tcp->win,0,10,
    //                   LIBNET_TCP_H + 20 + payload_s,(uint8_t *)payload,payload_s,l,0 );
    if(t==-1)
    {
        printf("cant build TCP header:%s\n",libnet_geterror(l));
        goto bad;
    }

    t=libnet_build_ipv4(LIBNET_IPV4_H+LIBNET_TCP_H+20+payload_s,0,242,0,64,IPPROTO_TCP,0, ip->ip_src.s_addr, ip->ip_dst.s_addr,NULL,0,l,0);

    if(t==-1)
    {
        printf("cant build IP header:%s\n",libnet_geterror(l));
        goto bad;
    }

    t=libnet_build_ethernet((u_int8_t *)ether->mac_dst, (u_int8_t *)ether->mac_src, ETHERTYPE_IP,NULL,0, l,0);

    if(t==-1)
    {
        printf("cant buid ethernet header:%s\n",libnet_geterror(l));
        goto bad;
    }

    c=libnet_write(l);
    if(c==-1)
    {
        printf("write error:%s\n",libnet_geterror(l));
        goto bad;
    }
    else
    {
#ifdef DEBUG
        printf("--------packet info--------\n");
        printf("src ip:%s\n", src_char_ip);
        printf("dst ip:%s\n", dst_char_ip);
        printf("src port:%d\n"
               "des port:%d\n",  ntohs(tcp->port_src), ntohs(tcp->port_dst));
        printf("tcp seq:%u\n", tcp->seq);
        printf("tcp window:%hu\n", tcp->win);
#endif
        printf("wrote %d byte TCP packet\n",c);
    }
    libnet_destroy(l);
    return 1;

    bad:
    libnet_destroy(l);
    return 0;

}