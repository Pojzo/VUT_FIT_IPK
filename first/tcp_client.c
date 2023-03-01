#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#include "tcp_client.h"

#define bufsize 1024

// run the tcp client with given host and port
void run_tcp_client(const char *host, int port) {
    printf("Running tcp client with host %s and port %d\n", host, port);
    (void) host;
    (void) port;
    
    int bytes_sent, bytes_received;

    int client_socket;
    struct hostent *server;
    struct sockaddr_in server_addr;
    
    // socklen_t server_addr_len;
    char buffer[bufsize];

    if ((server = gethostbyname(host)) == NULL) {
        fprintf(stderr, "ERROR: no such host as %s\n", host);
        exit(1);
    }
    // print the host name
    printf("Host name: %s\n", server->h_name);
    struct in_addr **addr_list = (struct in_addr **)server->h_addr_list;
    for (int i = 0; addr_list[i] != NULL; i++) {
        printf("IP Address: %s\n", inet_ntoa(*addr_list[i]));
    }
    
    
    bzero((char *) &server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&server_addr.sin_addr.s_addr, server->h_length);
    server_addr.sin_port = htons(port);

    printf("INFO: Server socket: %s : %d \n", inet_ntoa(server_addr.sin_addr), ntohs(server_addr.sin_port));
    
    if ((client_socket = socket(AF_INET, SOCK_STREAM, 0)) <= 0) {
        fprintf(stderr, "ERROR: Failed to create socket\n");
        exit(1);
    }

    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0) {
        fprintf(stderr, "ERROR: Failed to connect to server\n");
        exit(1);
    }
    // ---------------------------- send and receive message ----------------------------
    
    while (1) {
        bzero(buffer, bufsize);
        if (fgets(buffer, bufsize, stdin) == NULL) {
            fprintf(stderr, "ERROR: Failed to read message from stdin\n");
            exit(1);
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
