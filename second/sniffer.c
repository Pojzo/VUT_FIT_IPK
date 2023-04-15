#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <netpacket/packet.h>
#include <time.h>
#include <math.h>
#include <string.h>

#include "arg_handler.h"
#include "network_structures.h"

#define PROMISCUOUS_MODE 1
#define SNAPLEN 100
#define TIMEOUT 10000

#define FILTER_MAX_LEN 100

const char* TCP_FILTER_STRING = "tcp";
const char *UDP_FILTER_STRING = "udp";
const char *ARP_FILTER_STRING = "arp";
const char *ICMP4_FILTER_STRING = "icmp";
const char *ICMP6_FILTER_STRING = "icmp6";
const char *IGMP_FILTER_STRING = "igmp";
const char *MLD_FILTER_STRING = "mld";

bool at_least_one_filter;


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

#define SIZE_ETHERNET 14

static void print_mac(const unsigned char *mac) {
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        printf("%02x", mac[i]);
        if (i < ETHER_ADDR_LEN - 1) {
            printf(":");
        }
    }
    printf("\n");
}

static void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    (void) args;
    (void) packet;
    long sec = header->ts.tv_sec;
    long usec = header->ts.tv_usec;
    char *timestamp = format_time(sec, usec);
    printf("A packet was received\n");
    printf("timestamp: %s\n", timestamp);
    free(timestamp);

    unsigned int frame_length = header->len;

    const struct sniff_ethernet *ethernet; // The ethernet header
    const struct sniff_ip *ip; // The IP header
    const struct sniff_tcp *tcp;
    // const char *payload; // Packet payload

    // Define ethernet header
    ethernet = (struct sniff_ethernet*)(packet);

    // Define/compute IP header offset
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    
    // define tcp 
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + IP_HL(ip));

    // Extract source and destination IP addresses
    char src_ip_str[INET_ADDRSTRLEN], dst_ip_str[INET_ADDRSTRLEN];
    const unsigned char *src_mac_str;
    const unsigned char *dest_mac_str;

    unsigned short src_port = ntohs(tcp->th_sport);
    unsigned short dst_port = ntohs(tcp->th_dport);

    inet_ntop(AF_INET, &(ip->ip_src), src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->ip_dst), dst_ip_str, INET_ADDRSTRLEN);

    src_mac_str = ethernet->ether_dhost;
    dest_mac_str = ethernet->ether_shost;
    
    // print the mac addresses
    printf("src MAC: ");
    print_mac(src_mac_str);
    printf("dst MAC: ");
    print_mac(dest_mac_str);

    // print the frame length
    printf("frame length: %d\n", (int) frame_length);

    // print the source and destination ips
    printf("src IP: %s\n", src_ip_str);
    printf("dest IP: %s\n", dst_ip_str);


    // print the source and destination ports
    printf("src port: %d\n", (int) src_port); 
    printf("dest port: %d\n", (int) dst_port);

}

// add new filter to filter_exp
static void add_new_filter(char **filter_exp, const char *new_string)  {
    // if there's at least one filter, add or before the current filter expression
    const char *DELIMITER = " or ";
    const size_t DELIMITER_LEN = 4;
    const size_t new_string_len = strlen(new_string);
    const size_t filter_exp_len = strlen(*filter_exp);
    if (at_least_one_filter) {
        *filter_exp = (char *) realloc(*filter_exp, filter_exp_len + DELIMITER_LEN + new_string_len + 1);
        if (*filter_exp == NULL) exit(2);
        memcpy(*filter_exp + filter_exp_len, DELIMITER, DELIMITER_LEN);
        memcpy(*filter_exp + filter_exp_len + DELIMITER_LEN, new_string, new_string_len);
        (*filter_exp)[filter_exp_len + DELIMITER_LEN + new_string_len] = '\0';
        return;
    }

    *filter_exp = realloc(*filter_exp, new_string_len + 1);
    if (filter_exp == NULL) exit(2);
    memcpy(*filter_exp, new_string, new_string_len);
    (*filter_exp)[new_string_len] = '\0';

    at_least_one_filter = true;
}

static char *create_filter_exp(argument_t *arguments) {
    char *filter_exp = (char *) malloc(1);
    filter_exp[0] = '\0';

    uint8_t offset = 0;
    (void) offset;
    if (arguments->tcp) {
        add_new_filter(&filter_exp, TCP_FILTER_STRING);
    }
    if (arguments->udp) {
        add_new_filter(&filter_exp, UDP_FILTER_STRING);
    }
    if (arguments->arp) {
        add_new_filter(&filter_exp, ARP_FILTER_STRING);
    }
    if (arguments->icmp4) {
        add_new_filter(&filter_exp, ICMP4_FILTER_STRING);
    }
    if (arguments->icmp6) {
        add_new_filter(&filter_exp, ICMP6_FILTER_STRING);
    }
    if (arguments->igmp) {
        add_new_filter(&filter_exp, IGMP_FILTER_STRING);
    }
    if (arguments->mld) {
        add_new_filter(&filter_exp, MLD_FILTER_STRING);
    }
    return filter_exp;
}

int run_sniffer(argument_t *arguments) {
    pcap_if_t *all_devs = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 mask;		 // The netmask of our sniffing device
    bpf_u_int32 net;		// The IP of our sniffing device
    struct bpf_program fp;
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

    char *filter_exp = create_filter_exp(arguments);

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
    printf("The syntax was correct\n");
    free(filter_exp);
    return exit_free(arguments, all_devs, 0);
    pcap_loop(device_handle, arguments->n_packets, got_packet, NULL);
    /*
       packet = pcap_next(device_handle, &header);
       (void) packet;
       printf("Jacked a packet with length of [%d]\n", header.len);

       pcap_close(device_handle);
       */

    return exit_free(arguments, all_devs, 0);
}

// documentation : https://www.tcpdump.org/pcap.html

