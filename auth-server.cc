#include <fstream>
#include <iostream>

#include <getopt.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "crypto.h"

static const struct option long_options[] = {
	{"secret_key_filename", required_argument, NULL, 's'},
};

int main(int argc, char *argv[]) {
	std::string secret_key_filename;
	{
		int option, option_index;
		while ((option = getopt_long(argc, argv, "s:", long_options, &option_index)) != -1) {
			switch (option) {
				case 's':
					secret_key_filename = optarg;
					break;
			}
		}
	}

	std::string secret_key;
	{
		std::fstream secret_key_file(secret_key_filename, std::fstream::in);
		if (secret_key_file.fail()) {
			std::cerr << "Failed to open secret key file" << std::endl;
			return 1;
		}
		secret_key_file >> secret_key;
	}

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

	CryptoPubServer server(fd, secret_key);
	server.Loop();
}
