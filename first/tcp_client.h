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



#ifndef TCP_CLIENT_H
#define TCP_CLIENT_H

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <netdb.h>
#include <netinet/in.h>

typedef struct sockaddr_in sockaddr_in_t;
typedef struct hostent hostent_t;

typedef struct sockaddr_in* sockaddr_in_ptr;
typedef struct hostent* hostent_ptr;

typedef struct sockaddr* sockaddr_ptr;

void run_tcp_client(char* host, int port);

#endif
