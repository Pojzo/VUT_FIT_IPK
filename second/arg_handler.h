#ifndef ARG_HANDLER_H
#define ARG_HANDLER_H

#include <stdint.h>
#include <stdbool.h>

typedef struct arguments {
    bool interface_only;
    char *interface;
    uint16_t port;
    uint16_t n_packets;
    bool port_specified;
    bool n_packets_specified;
    bool tcp;
    bool udp;
    bool arp;
    bool ndp;
    bool icmp4;
    bool icmp6;
    bool igmp;
    bool mld;

} arguments_t;

arguments_t *parse_arguments(int argc, char *argv[]);
void arguments_free(arguments_t *arguments);


#endif
