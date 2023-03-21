#include "udp_client.h"
#include "common.h"

#define bufsize 1024

void print_bits(char *buffer, size_t buffer_len);

// run the udp client given the host and port
void run_udp_client(const char *host, int port) {
    int client_socket, bytes_sent, bytes_received;
    socklen_t serverlen;
    struct hostent *server;
    struct sockaddr_in server_address;

    char buf[bufsize];

    const char *server_hostname = host;
    int server_port = port;

    if ((server = gethostbyname(server_hostname)) == NULL) {
        fprintf(stderr, "ERROR: no such host as %s\n", server_hostname);
        exit(1);
    }

    bzero((char *) &server_address, sizeof(server_address));
    server_address.sin_family = AF_INET;
    bcopy((char *) server->h_addr, (char *) &server_address.sin_addr.s_addr, server->h_length);
    server_address.sin_port = htons(server_port);
    
    printf("INFO: Server socket: %s : %d \n", inet_ntoa(server_address.sin_addr), ntohs(server_address.sin_port));


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
        char *payload = malloc(total_len);

        memcpy(payload, &opcode, sizeof(opcode));
        memcpy(payload + sizeof(opcode), &buffer_len, sizeof(buffer_len));

        memcpy(payload + sizeof(opcode) + sizeof(buffer_len), buf, buffer_len);

        // print_bits(payload, total_len);
        /*
           printf("\n");
           printf("Payload: ");
           for (int i = 0; i < total_len; i++) {
           for (int j = 7; j >= 0; j--) {
           if (payload[i] & (1 << j)) {
           printf("1");
           } else {
           printf("0");
           }
           }
           printf(" ");
           }
           printf("\n");
           */

        serverlen = sizeof(server_address);
        bytes_sent = sendto(client_socket, payload, total_len, 0, (struct sockaddr *) &server_address, serverlen);
        if (bytes_sent < 0) {
            fprintf(stderr, "ERROR: could not send message\n");
            exit(1);
        }
        // printf("Payload has been sent\n");

        free(payload);
        bzero(buf, bufsize);
        bytes_received = recvfrom(client_socket, buf, bufsize, 0, (struct sockaddr *) &server_address, &serverlen);
        if (bytes_received < 0) {
            fprintf(stderr, "ERROR: could not receive message\n");
            exit(1);
        }
        // print_bits(buf, bytes_received);

        uint8_t recv_opcode = buf[0];
        uint8_t status_code = buf[1];
        uint8_t recv_buffer_len = buf[2];
        
        if ((int)status_code == 1) {
            fprintf(stderr, "ERROR: invalid message\n");
            exit(1);
        }

        // printf("Opcode: %d\n", recv_opcode);
        // printf("Status Code: %d\n", status_code);
        //printf("Payload Length: %d\n", recv_buffer_len);
        char *recv_buffer = malloc(recv_buffer_len);
        memcpy(recv_buffer, buf + 3, recv_buffer_len);

        (void) recv_opcode;
        printf("OK:");
        for (int i = 0; i < recv_buffer_len; i++) {
            printf("%c", recv_buffer[i]);
        }

        printf("\n");
    }
    // close everything
    close(client_socket);
}

void print_bits(char *buffer, size_t buffer_len) {
    for (size_t i = 0; i < buffer_len; i++) {
        for (int j = 7; j >= 0; j--) {
            if (buffer[i] & (1 << j)) {
                printf("1");
            } else {
                printf("0");
            }
        }
        printf(" ");
    }
    printf("\n");
}
