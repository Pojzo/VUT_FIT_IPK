#include "common.h"
#include "udp_client.h"


void print_bits(char *buffer, size_t buffer_len);

static inline int get_client_socket() {
    int client_socket;
    if ((client_socket = socket(AF_INET, SOCK_STREAM, 0)) <= 0) {
        fprintf(stderr, "ERROR: Failed to create socket\n");
        exit(1);
    }
    return client_socket;
}



// run the udp client given the host and port
void run_udp_client(const char *host, int port) {
    int bytes_sent, bytes_received;
    socklen_t serverlen;
    sockaddr_in_t server_address;

    char buf[bufsize];
    
    hostent_ptr server = get_server_host(host);
    sockaddr_in_t server_addr = get_server_address(server, port);

    int client_socket = get_client_socket();
    printf("INFO: Client socket: %d \n", client_socket);
    printf("INFO: Server socket: %s : %d \n", inet_ntoa(server_addr.sin_addr), ntohs(server_addr.sin_port));
    
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

        printf("%d\n", __LINE__);
        memcpy(payload + sizeof(opcode) + sizeof(buffer_len), buf, buffer_len);

        serverlen = sizeof(server_address);
        printf("%d\n", __LINE__);
        bytes_sent = sendto(client_socket, payload, total_len, 0, (sockaddr_ptr) &server_address, serverlen);
        printf("%d\n", __LINE__);
        if (bytes_sent < 0) {
            fprintf(stderr, "ERROR: could not send message\n");
            exit(1);
        }
        // printf("Payload has been sent\n");

        free(payload);
        printf("%d\n", __LINE__);
        bzero(buf, bufsize);
        printf("%d\n", __LINE__);
        bytes_received = recvfrom(client_socket, buf, bufsize, 0, (sockaddr_ptr) &server_address, &serverlen);
        printf("%d\n", __LINE__);
        if (bytes_received < 0) {
            fprintf(stderr, "ERROR: could not receive message\n");
            exit(1);
        }
        // print_bits(buf, bytes_received);
        printf("%d\n", __LINE__);
        uint8_t recv_opcode = buf[0];
        uint8_t status_code = buf[1];
        uint8_t recv_buffer_len = buf[2];
        
        if ((int)status_code == 1) {
            fprintf(stderr, "ERROR: invalid message\n");
            exit(1);
        }

        printf("Opcode: %d\n", recv_opcode);
        printf("Status Code: %d\n", status_code);
        printf("Payload Length: %d\n", recv_buffer_len);
        char *recv_buffer = malloc(recv_buffer_len);
        memcpy(recv_buffer, buf + 3, recv_buffer_len);

        printf("Received message: ");
        for (int i = 0; i < recv_buffer_len; i++) {
            printf("%c", recv_buffer[i]);
        }

        printf("\n");
    }
    // close the socket
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
