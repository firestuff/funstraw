#include <iostream>

#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "crypto.h"

int main() {
	int fd = socket(PF_INET6, SOCK_STREAM, 0);

	int optval = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));

	struct sockaddr_in6 server_addr = {0};
 	server_addr.sin6_family = AF_INET6;
 	server_addr.sin6_addr = in6addr_any;
 	server_addr.sin6_port = htons(4990);

	if (bind(fd, (struct sockaddr*) &server_addr, sizeof(server_addr))) {
		perror("bind");
		return 1;
	}

	if (listen(fd, 256)) {
		perror("listen");
		return 1;
	}

	CryptoPubServer server(fd, "abcde");
	server.Loop();
}
