/*
Client program for the subject IPK at VUT FIT
Copyright (C) 2023  Peter Kovac

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

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
    
    if (strcmp(mode, "tcp") == 0) {
        run_tcp_client(host, atoi(port)); 
    } else {
        run_udp_client(host, atoi(port));
    }
    return 0;
}
