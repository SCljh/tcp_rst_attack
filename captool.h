//
// Created by root on 2019/11/29.
//

#ifndef TCP_RST_CAPTOOL_H
#define TCP_RST_CAPTOOL_H

#include "attack_tool.h"

int selfFiltter(u_short *packet);
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);


#endif //TCP_RST_CAPTOOL_H
