#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <netpacket/packet.h>
#include <time.h>
#include <math.h>
#include <string.h>
#include <ctype.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

#include "arg_handler.h"

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

static void hex_dump(const u_char *packet, int len) {
    int i, j;

    for (i = 0; i < len; i += 16) {
        printf("%06x: ", i);
        for (j = 0; j < 16; j++) {
            if (i + j < len) {
                printf("%02x ", packet[i+j]);
            } else {
                printf("   ");
            }
        }
        printf(" ");
        for (j = 0; j < 16; j++) {
            if (i + j < len) {
                u_char c = packet[i+j];
                printf("%c", isprint(c) ? c : '.');
            }
        }
        printf("\n");
    }
}


static void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    (void) args;
    long sec = header->ts.tv_sec;
    long usec = header->ts.tv_usec;
    char *timestamp = format_time(sec, usec);
    printf("timestamp: %s\n", timestamp);
    free(timestamp);

    int frame_length = header->len;

    const struct ether_header *ethernet = (struct ether_header*) (packet);
    const struct iphdr *ip_header = (struct iphdr*)(packet + SIZE_ETHERNET);
    uint16_t ip_header_len = ip_header->ihl * 4;

    struct udphdr *udp_header = (struct udphdr*)(packet + SIZE_ETHERNET + ip_header_len);
    struct tcphdr *tcp_header = (struct tcphdr*)(packet + SIZE_ETHERNET + ip_header_len);
    struct icmphdr *icmp_header = (struct icmphdr*)(packet + SIZE_ETHERNET + ip_header_len);
    
    (void) udp_header;
    (void) tcp_header;
    (void) icmp_header;

    uint16_t src_port;
    uint16_t dst_port;
    unsigned char protocol = ip_header->protocol;
    printf("%s\n", packet);
    switch (protocol) {
        case IPPROTO_TCP:
            printf("This is a TCP packet\n");
            src_port = ntohs(tcp_header->source);
            dst_port = ntohs(tcp_header->dest);
            break;
        case IPPROTO_UDP:
            // printf("This is a UDP packet\n");
            src_port = ntohs(tcp_header->source);
            dst_port = ntohs(tcp_header->dest);
            break;
        case IPPROTO_ICMP:
            printf("This is a ICMP packet\n");
            break;
        case IPPROTO_ICMPV6:
            break;

        default:
            break;
    }

    // define tcp 

    // Extract source and destination IP addresses
    unsigned char src_mac[18];
    unsigned char dst_mac[18];

    char source_ip_str[INET_ADDRSTRLEN];
    char dest_ip_str[INET_ADDRSTRLEN];

    sprintf(src_mac, "%02x:%02x:%02x:%02x:%02x:%02x", ethernet->ether_shost[0], ethernet->ether_shost[1], ethernet->ether_shost[2], ethernet->ether_shost[3], ethernet->ether_shost[4], ethernet->ether_shost[5]);
    sprintf(dst_mac, "%02x:%02x:%02x:%02x:%02x:%02x", ethernet->ether_dhost[0], ethernet->ether_dhost[1], ethernet->ether_dhost[2], ethernet->ether_dhost[3], ethernet->ether_dhost[4], ethernet->ether_dhost[5]);

    inet_ntop(AF_INET, &(ip_header->saddr), source_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->daddr), dest_ip_str, INET_ADDRSTRLEN);

    // print the mac addresses
    printf("src MAC: %s\n", src_mac);
    printf("dst MAC: %s\n", dst_mac);

    // print the frame length
    printf("frame length: %d\n", (int) frame_length);

    // print the source and destination ips
    printf("src IP: %s\n", source_ip_str);
    printf("dest IP: %s\n", dest_ip_str);

    // print the source and destination ports
    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
        printf("src port: %hu\n", src_port); 
        printf("dest port: %hu\n", dst_port);
    }

    unsigned char buffer[16];

    for (size_t i = 0; i < frame_length; i++) {
        if (i % 16 == 0) {
            printf(" ");
            if (i != 0) {
                for (size_t x = 0; x < 16; x++) {
                    if (isprint(buffer[x])) {
                        printf("%c", buffer[x]);
                    } else {
                        printf(".");
                    }
                }
            }
            printf("\n0x%04x: ", i);
        }

        buffer[i % 16] = packet[i];
        printf("%02x ", packet[i]);
    }

    // Print any remaining bytes in the buffer
    for (int i = frame_length % 16; i < 16; i++) {
        printf("   ");
    }
    for (int i = frame_length - (frame_length % 16); i < frame_length; i++) {
        if (isprint(buffer[i % 16])) {
            printf("%c", buffer[i % 16]);
        } else {
            printf(".");
        }
    }
    printf("\n");
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
        if (arguments->port_specified) {
            char buf[15];
            sprintf(buf, "%s port %d", TCP_FILTER_STRING, (int) arguments->port);
            add_new_filter(&filter_exp, buf);
        }
        else {
            add_new_filter(&filter_exp, TCP_FILTER_STRING);
        }
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
    
    if (arguments->ndp && arguments->mld) {
        char buf[100];
        sprintf(buf, "%s and (icmp6[0] == 135 or icmp6[0] == 136 or icmp6[0]== 130 or icmp6[0] == 131)", ICMP6_FILTER_STRING);
        add_new_filter(&filter_exp, buf);
        // nestaram fakt more
        goto jump;
    }

    if (arguments->ndp) {
        char buf[45];
        sprintf(buf, "%s and (icmp6[0] == 135 or icmp6[0] == 136)", ICMP6_FILTER_STRING);
        add_new_filter(&filter_exp, buf);
        goto jump;
    }
    if (arguments->mld) {
        char buf[45];
        sprintf(buf, "%s and (icmp6[0]== 130 or icmp6[0] == 131)", ICMP6_FILTER_STRING);
        add_new_filter(&filter_exp, buf);
        goto jump;
    }
    if (arguments->icmp6) {
        add_new_filter(&filter_exp, ICMP6_FILTER_STRING);
    }
jump:

    if (arguments->igmp) {
        add_new_filter(&filter_exp, IGMP_FILTER_STRING);
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
    printf("This is the filter expression %s\n", filter_exp);

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
    printf("Filter: %s\n", filter_exp);
    // free(filter_exp);
    pcap_loop(device_handle, arguments->n_packets, got_packet, NULL);

    return exit_free(arguments, all_devs, 0);
}

// documentation : https://www.tcpdump.org/pcap.html

