#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include "arg_handler.h"


static void list_interfaces(pcap_if_t *all_devs) {
    pcap_if_t *cur_dev = all_devs;
    while (cur_dev != NULL) {
        printf("%s\n", cur_dev->name);
        cur_dev = cur_dev->next;
    }
}

int run_sniffer(argument_t *arguments) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *all_devs = NULL;

    int dev = pcap_findalldevs(&all_devs, errbuf);
    if (dev == PCAP_ERROR) {
        fprintf(stderr, "Could not list devices\n");
        return 1;
    }

    // if this is true, list all interfaces
    if (arguments->interface_only) {
        list_interfaces(all_devs);
    }

    pcap_freealldevs(all_devs);
    
    return 0;
}
