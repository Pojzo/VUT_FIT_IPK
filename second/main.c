#include <stdio.h>
#include "arg_handler.h"
#include <pcap/pcap.h>


int main(int argc, char *argv[]) {
    argument_t *arguments = parse_arguments(argc, argv);
    (void) arguments;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *all_devs = NULL;

    int dev = pcap_findalldevs(&all_devs, errbuf);
    if (dev == PCAP_ERROR) {
        fprintf(stderr, "Could not list devices\n");
        return 1;
    }
    pcap_if_t *cur_dev = all_devs;
    while (cur_dev != NULL) {
        printf("Device name: %s\nDevice description: %s\n\n",
                cur_dev->name, 
                cur_dev->description == NULL ? "None" : cur_dev->description);
        cur_dev = cur_dev->next;
    }

    pcap_freealldevs(all_devs);

    return 0;
}
