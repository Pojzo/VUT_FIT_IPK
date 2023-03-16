#include "common.h"

void error_message(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
}


// returns pointer to the hostent struct
hostent_ptr get_server_host(const char *host) {
    hostent_ptr server;
    if ((server = gethostbyname(host)) == NULL) {
        error_message("ERROR: no such host as %s\n", host);
        exit(1);
    }
    
    return server;
}

// returns the server address struct
sockaddr_in_t get_server_address(hostent_ptr server, int port) {
    sockaddr_in_t server_addr;

    bzero((char *) &server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&server_addr.sin_addr.s_addr, server->h_length);
    server_addr.sin_port = htons(port);

    return server_addr;
}


