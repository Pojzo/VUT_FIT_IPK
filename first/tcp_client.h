#ifndef TCP_CLIENT_H
#define TCP_CLIENT_H


void sigint_handler(int sig);
void run_tcp_client(const char *host, int port);

#endif
