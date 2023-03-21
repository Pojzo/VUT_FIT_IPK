Documentation of the first project of IPK 2022/2023
Name: Peter Kováč
Login: xkovac66

# Overview
The goal of this project was to implement a client for a remote calculator, that is capable of using both *TCP* and *UDP* protocols. The programming language I chose for the project is <ins>C</ins>, as I have a lot of experience with it from previous projects. 

## Libraries
The primary library used in this project is `socket.h`, which is essential for implementing network communication between a server and a client. Other networking-related libraries used in the project include `netinet/in.h`, `arpa/inet.h`, `netdb.h`, and `unistd.h`, which provide necessary functionalities such as defining internet address structures, converting between binary and text IP address representations, resolving addresses, and handling file descriptors and system calls.

## File structure
The source file `main.c` handles arguments and starts the client (`tcp_client.c` or `udp_client.c`) in a mode specified by the user. 

##### Functions implemented in tcp_client.c
```c
static hostent_ptr get_server_host(const char *host)
void run_tcp_client(const char *host, int port)
static sockaddr_in_t get_server_address(hostent_ptr server, int port)        
static inline int get_client_socket()
static void client_connect(int client_socket, sockaddr_ptr server_addr, sockelen_t server_addr_len)
void sigint_handler(int sig)
```

##### functions implemented in udp_client.c
```c
static hostent_ptr get_server_host(const char *host)
static sockaddr_in_t get_server_address(hostent_ptr server, int port)
void sigint_handler(int sig)
void run_udp_client(const char *host, int port)
```

# TCP Client

*TCP* client was easier to implement than the *UDP* client, because once connection is established, client and server can communicate with each other with a reliable and ordered stream of data, <ins>with error checking and automatic retransmission of lost packets</ins>.
The client starts by checking whether the given client is valid and then tries to establish a connection.
```c
// create socket
int client_socket;
if ((client_socket = socket(AF_INET, SOCK_STREAM, 0)) <= 0) {
	fprintf(stderr, "ERROR: Failed to create socket\n");
	exit(1);
 }
 ```
 ```c
 // try to connect to the server
if (connect(client_socket, server_addr, server_addr_len) != 0) {
	fprintf(stderr, "ERROR: Failed to connect to server\n");
	exit(1);
}
```

The function`send()` was used to send a message to the server.
```c
bytes_sent = send(client_socket, buffer, strlen(buffer), 0);
// ... check for errors
```
For receiving messages, the function recv was used.
```c
bytes_received = recv(client_socket, buffer, bufsize, 0);
// ... check for errors
```
To close the socket in both TCP and UDP
```c
close(client_socket);
```

# UDP Client
As opposed to the *TCP* protocol, *UDP* protocol is **connectionless**, which means <ins>error handling and and retransmission of lost packets has to be implemented</ins>.  Based on the *IPK Calculator Protocol*, the first 8 bits should contain the **opcode**, the next 8 bits the **payload length** and the rest of the message should comprise the actual **payload data**. For the *opcode* and *payload length*, I used the `uint8_t` data structure. 

```c
uint8_t opcode = 0;
uint8_t buffer_len = strlen(buf)
```

To create the final payload, `char* payload` was dynamically allocated with required size.
```c
int total_len = 2 + buffer_len; // 2 bytes for opcode and payload length
char *payload = malloc(total_len);

memcpy(payload, &opcode, sizeof(opcode)); // copy the opcode
memcpy(payload + sizeof(opcode), &buffer_len, sizeof(buffer_len)); // copy the payload length
memcpy(payload + sizeof(opcode) + sizeof(buffer_len), buf, buffer_len); // create the final payload
```

The *payload* is then sent using `sendto()`. If *bytes_sent* is less than zero, throw an error. 
 ```c
bytes_sent = sendto(client_socket, payload, total_len, 0, (sockaddr_ptr) &server_address, serverlen);
// ... error checking
```

To receive a message, similar technique was used. 
```c
bytes_received = recvfrom(client_socket, buf, bufsize, 0, (sockaddr_ptr) &server_address, &serverlen);
// check if the message was received correctly
// ...
uint8_t recv_opcode = buf[0];
uint8_t status_code = buf[1];
uint8_t recv_buffer_len = buf[2];
```

# Testing
Testing of the implementation involved only manual tests without any automated tests. 
There is a server running on `merlin.fit.vutbr.cz` at port `10002` that simulates the functionality of the remote calculator, which was used for testing the commands using both *TCP* and *UDP* protocols. 

# Bibliography
Demo examples at [https://git.fit.vutbr.cz/NESFIT/IPK-Projekty](https://git.fit.vutbr.cz/NESFIT/IPK-Projekty)
