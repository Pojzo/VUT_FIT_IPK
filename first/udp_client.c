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


#include "udp_client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>

#define bufsize 1024

static int client_socket;
char *recv_buffer;
char *payload;

void sigint_handler_udp(int sig) {
    (void) sig;
    free(recv_buffer);
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

// run the udp client given the host and port
void run_udp_client(const char *host, int port) {
    signal(SIGINT, sigint_handler_udp);
    int bytes_sent, bytes_received;

    socklen_t serverlen;

    struct hostent *server = get_server_host(host);
    struct sockaddr_in server_address = get_server_address(server, port);

    char buf[bufsize];
    
    if ((client_socket = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        fprintf(stderr, "ERROR: could not create socket\n");
        exit(1);
    }
    
    while (1) {
        bzero(buf, bufsize);
        // printf("Enter a message: ");
        fgets(buf, bufsize, stdin);
        uint8_t opcode = 0;
        uint8_t buffer_len = strlen(buf);

        int total_len = 2 + buffer_len;
        
        payload = malloc(total_len);

        memcpy(payload, &opcode, sizeof(opcode));
        memcpy(payload + sizeof(opcode), &buffer_len, sizeof(buffer_len));

        memcpy(payload + sizeof(opcode) + sizeof(buffer_len), buf, buffer_len);

        serverlen = sizeof(server_address);
        bytes_sent = sendto(client_socket, payload, total_len, 0, (struct sockaddr *) &server_address, serverlen);
        if (bytes_sent < 0) {
            fprintf(stderr, "ERROR: could not send message\n");
            exit(1);
        }
        // payload has been setn
        
        bzero(buf, bufsize);
        bytes_received = recvfrom(client_socket, buf, bufsize, 0, (struct sockaddr *) &server_address, &serverlen);
        // check if the message is valid
        if (bytes_received < 0) {
            fprintf(stderr, "ERROR: could not receive message\n");
            exit(1);
        }
        free(payload);

        uint8_t recv_opcode = buf[0];
        uint8_t status_code = buf[1];
        uint8_t recv_buffer_len = buf[2];
        
        if ((int)status_code == 1) {
            fprintf(stderr, "ERROR: invalid message\n");
            exit(1);
        }

        // copy the buffer
        recv_buffer = malloc(recv_buffer_len);
        memcpy(recv_buffer, buf + 3, recv_buffer_len);

        (void) recv_opcode;
        // print the received message
        printf("OK:");
        for (int i = 0; i < recv_buffer_len; i++) {
            printf("%c", recv_buffer[i]);
        }

        printf("\n");
    }
    // close everything
    free(payload);
    free(recv_buffer);
    close(client_socket);
}
