#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <netdb.h>
#include <netinet/in.h>

#define bufsize 1024

typedef struct sockaddr_in sockaddr_in_t;
typedef struct hostent hostent_t;

typedef struct sockaddr_in* sockaddr_in_ptr;
typedef struct hostent* hostent_ptr;

typedef struct sockaddr* sockaddr_ptr;

void error_message(const char *format, ...);
hostent_ptr get_server_host(const char *host);
sockaddr_in_t get_server_address(hostent_ptr server, int port);

#endif
