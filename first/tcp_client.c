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


#include "tcp_client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>

#define bufsize 1024

static int client_socket;

void sigint_handler_tcp(int sig) {
    (void) sig;
    const char *bye_msg = "BYE";
    int bytes_sent = send(client_socket, bye_msg, strlen(bye_msg), 0);
    (void) bytes_sent;

    close(client_socket);
    exit(0);
}


static void error_message(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
}


// returns pointer to the hostent struct
static hostent_ptr get_server_host(const char *host) {
    hostent_ptr server;
    if ((server = gethostbyname(host)) == NULL) {
        error_message("ERROR: no such host as %s\n", host);
        exit(1);
    }

    return server;
}

// returns the server address struct
static sockaddr_in_t get_server_address(hostent_ptr server, int port) {
    sockaddr_in_t server_addr;

    bzero((char *) &server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&server_addr.sin_addr.s_addr, server->h_length);
    server_addr.sin_port = htons(port);

    return server_addr;
}

static inline int get_client_socket() {
    int client_socket;
    if ((client_socket = socket(AF_INET, SOCK_STREAM, 0)) <= 0) {
        fprintf(stderr, "ERROR: Failed to create socket\n");
        exit(1);
    }
    return client_socket;
}

// if the connection to the server fails, then exit with error code 1
static void client_connect(int client_socket, sockaddr_ptr server_addr, socklen_t server_addr_len) {
    if (connect(client_socket, server_addr, server_addr_len) != 0) {
        fprintf(stderr, "ERROR: Failed to connect to server\n");
        exit(1);
    }
}


// run the tcp client with given host and port
void run_tcp_client(char *host, int port) {
    signal(SIGINT, sigint_handler_tcp);
    int bytes_sent, bytes_received;
    char buffer[bufsize];

    hostent_ptr server = get_server_host(host);

    sockaddr_in_t server_addr = get_server_address(server, port);

    client_socket = get_client_socket();

    client_connect(client_socket, (sockaddr_ptr) &server_addr, sizeof(server_addr));

    // ---------------------------- send and receive message ----------------------------

    while (1) {
        bzero(buffer, bufsize);
        if (fgets(buffer, bufsize, stdin) == NULL) {
            fprintf(stderr, "ERROR: Failed to read message from stdin\n");
            break;
        }

        bytes_sent = send(client_socket, buffer, strlen(buffer), 0);
        if (bytes_sent < 0) {
            fprintf(stderr, "ERROR: Failed to send message to server\n");
            exit(1);
        }
        bzero(buffer, bufsize);
        bytes_received = recv(client_socket, buffer, bufsize, 0);
        if (bytes_received < 0) {
            fprintf(stderr, "ERROR: Failed to receive message from server\n");
            exit(1);
        }

        printf("%s", buffer);

        if (strncmp(buffer, "BYE", 3) == 0) {
            break;
        }
    }
    close(client_socket);
} 

