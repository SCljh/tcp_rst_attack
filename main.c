//
// Created by root on 2019/11/29.
//

#include "attack_tool.h"
#include "captool.h"
#include "libnetool.h"

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