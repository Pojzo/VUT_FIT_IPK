#ifndef ARG_HANDLER_H
#define ARG_HANDLER_H

#include <stdint.h>
#include <stdbool.h>

typedef struct argument {
    bool interface_only;
    char *interface;
    uint16_t port;
    uint16_t n_packets;
    bool port_specified;
    bool n_packets_specified;
    bool tcp;
    bool udp;
    bool arp;
    bool icmp4;
    bool icmp6;
    bool igmp;
    bool mld;

} argument_t;

argument_t *parse_arguments(int argc, char *argv[]);


#endif
