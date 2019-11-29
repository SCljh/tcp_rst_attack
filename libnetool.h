//
// Created by root on 2019/11/29.
//

#ifndef TCP_RST_LIBNETOOL_H
#define TCP_RST_LIBNETOOL_H

#include "attack_tool.h"

int buildRstPacket(struct ip_data *ip, struct tcp_data *tcp);
int buildRstPacket_e(struct ip_data *ip, struct tcp_data *tcp, struct ethernet_data *ether);

#endif //TCP_RST_LIBNETOOL_H
