#include "common.h"
#include "tcp_client.h"


volatile sig_atomic_t should_exit = 0;

 /*
    struct in_addr **addr_list = (struct in_addr **)server->h_addr_list;
    for (int i = 0; addr_list[i] != NULL; i++) {
        printf("IP Address: %s\n", inet_ntoa(*addr_list[i]));
    }
*/

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
void run_tcp_client(const char *host, int port) {
    int bytes_sent, bytes_received;
    char buffer[bufsize];

    hostent_t *server = get_server_host(host);

    sockaddr_in_t server_addr = get_server_address(server, port);

    printf("INFO: Server socket: %s : %d \n", inet_ntoa(server_addr.sin_addr), ntohs(server_addr.sin_port));

    int client_socket = get_client_socket();

    client_connect(client_socket, (sockaddr_ptr) &server_addr, sizeof(server_addr));

    // ---------------------------- send and receive message ----------------------------

    while (1) {
        if (should_exit) {
            const char *bye_msg = "BYE";
            bytes_sent = send(client_socket, bye_msg, strlen(bye_msg), 0);
            // we don't care if it was sent or not
            break;
        }
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
    printf("Closed connection to server\n");
} 

void sigint_handler(int sig) {
    (void) sig;
    should_exit = 1;
}

