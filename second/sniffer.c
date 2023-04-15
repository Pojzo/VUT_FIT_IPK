#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <time.h>
#include <math.h>

#include "arg_handler.h"

#define PROMISCUOUS_MODE 1
#define SNAPLEN 100
#define TIMEOUT 10000


// free all structures and return 'return_code'
static int exit_free(argument_t *arguments, pcap_if_t *all_devs, int return_code) {
    arguments_free(arguments);
    pcap_freealldevs(all_devs);
    return return_code;
}

// list all interfaces and return 0 if successful 
static int list_interfaces(pcap_if_t *all_devs) {
    char errbuf[PCAP_ERRBUF_SIZE];

    int dev = pcap_findalldevs(&all_devs, errbuf);
    pcap_if_t *cur_dev = all_devs;
    if (dev == PCAP_ERROR) {
        fprintf(stderr, "Could not list devices\nError message: %s\n", errbuf);
        return 1;
    }

    while (cur_dev != NULL) {
        printf("%s\n", cur_dev->name);
        cur_dev = cur_dev->next;
    }
    return 0;
}

#define TIMESTAMP_BUFFER_LEN 80

static char* format_time(long seconds, long microseconds) {
       char* buffer = malloc(sizeof(char) * 80);
    struct tm timeinfo;

    localtime_r(&seconds, &timeinfo);
    strftime(buffer, 80, "%Y-%m-%dT%H:%M:%S", &timeinfo);

    char* formatted_time = malloc(sizeof(char) * 32);
    sprintf(formatted_time, "%s.%03lu", buffer, microseconds);

    char timezone[8];
    strftime(timezone, 8, "%z", &timeinfo);

    char offset_sign = timezone[0];
    int offset_hours = atoi(&timezone[1]) / 100;
    int offset_minutes = atoi(&timezone[1]) % 100;

    char* final_time = malloc(sizeof(char) * 32);
    sprintf(final_time, "%s%c%02d:%02d", formatted_time, offset_sign, offset_hours, offset_minutes);

    free(buffer);
    free(formatted_time);

    return final_time;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    (void) args;
    (void) packet;
    long sec = header->ts.tv_sec;
    long usec = header->ts.tv_usec;
    char *timestamp = format_time(sec, usec);
    printf("A packet was received\n");
    printf("Timestamp: %s\n", timestamp);
    free(timestamp);
}

int run_sniffer(argument_t *arguments) {
    pcap_if_t *all_devs = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 mask;		 // The netmask of our sniffing device
    bpf_u_int32 net;		// The IP of our sniffing device
    struct bpf_program fp;
    char *filter_exp = "ip proto 1";	// The filter expression 
    pcap_t *device_handle = NULL;
    struct pcap_pkthdr header;
    const u_char *packet;		// The actual pack
    (void) packet;
    (void) header;

    // if this is true, list all interfaces
    if (arguments->interface_only && arguments->interface == NULL) {
        // if there has been an error
        if (list_interfaces(all_devs)) return exit_free(arguments, all_devs, 1);

        return exit_free(arguments, all_devs, 0);
    }

    if (pcap_lookupnet(arguments->interface, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", arguments->interface);
        return exit_free(arguments, all_devs, 1);
    }

    // try to open the device for capturing packets
    device_handle = pcap_open_live(arguments->interface, SNAPLEN, PROMISCUOUS_MODE, TIMEOUT, errbuf);

    if (device_handle == NULL) {
        fprintf(stderr, "There has been an error opening %s\nError message: %s\n", arguments->interface, errbuf);
        return exit_free(arguments, all_devs, 1);
    }


    // compile the filter
    int compile_result = pcap_compile(device_handle, &fp, filter_exp, 0, net);
    if (compile_result == -1) {
        fprintf(stderr, "Couldn't parse filter %s\nError message: %s\n", filter_exp, pcap_geterr(device_handle));
        return exit_free(arguments, all_devs, 1);
    }

    // try to apply the filter
    int filter_result = pcap_setfilter(device_handle, &fp);
    if (filter_result == -1) {
        fprintf(stderr, "Couldn't install filter %s\nError message: %s\n", filter_exp, pcap_geterr(device_handle));
        return exit_free(arguments, all_devs, 1);
    }
    pcap_loop(device_handle, 1, got_packet, NULL);
    /*
       packet = pcap_next(device_handle, &header);
       (void) packet;
       printf("Jacked a packet with length of [%d]\n", header.len);

       pcap_close(device_handle);
       */

    return exit_free(arguments, all_devs, 0);
}

// documentation : https://www.tcpdump.org/pcap.html

