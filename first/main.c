#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "tcp_client.h"
#include "udp_client.h"

/*
The client is started using: ipkcpc -h <host> -p <port> -m <mode> where host is the IPv4 address of the server, port the server port, and mode either tcp or udp (e.g., ipkcpc -h 1.2.3.4 -p 2023 -m udp).
*/

void print_usage(const char *message) {
    if (message != NULL) {
        fprintf(stderr, "%s\n", message);
    }
    fprintf(stderr, "Usage: ipkcpc -h <host> -p <port> -m <mode>\n");
}

// print errors to stderr
int main(int argc, char *argv[]) {
    if (argc != 7) {
        print_usage("Invalid number of arguments");
        exit(1);
    }

    char *host_arg = argv[1];
    if (strcmp(host_arg, "-h") != 0) {
        print_usage("Invalid host argument");
        exit(1);
    }

    char *host = argv[2];

    char *port_arg = argv[3];
    if (strcmp(port_arg, "-p") != 0) {
        print_usage("Invalid port argument");
        exit(1);
    }

    char *port = argv[4];
    // check if port is number
    for (size_t i = 0; i < strlen(port); i++) {
        if (port[i] < '0' || port[i] > '9') {
            print_usage("Invalid port");
            exit(1);
        }
    }

    char *mode_arg = argv[5];
    if (strcmp(mode_arg, "-m") != 0) {
        print_usage("Invalid mode argument");
        exit(1);
    }

    char *mode = argv[6];
    if (strcmp(mode, "tcp") != 0 && strcmp(mode, "udp") != 0) {
        print_usage("Invalid mode");
        exit(1);
    }
    
    printf("host: %s, port: %s, mode: %s\n", host, port, mode);
    if (strcmp(mode, "tcp") == 0) {
        run_tcp_client(host, atoi(port)); 
    } else {
        run_udp_client(host, atoi(port));
    }
    return 0;
}
