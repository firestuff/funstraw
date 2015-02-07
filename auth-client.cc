#include <fstream>
#include <iostream>

#include <getopt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "crypto.h"

static const struct option long_options[] = {
	{"secret_key_filename", required_argument, NULL, 's'},
	{"server_public_key_filename", required_argument, NULL, 'r'},
	{"server_address", required_argument, NULL, 'a'},
	{"server_port", required_argument, NULL, 't'},
};

int main(int argc, char *argv[]) {
	std::string secret_key_filename;
	std::string public_key_filename;
	std::string server_public_key_filename;
	std::string server_address;
	std::string server_port;
	{
		int option, option_index;
		while ((option = getopt_long(argc, argv, "s:", long_options, &option_index)) != -1) {
			switch (option) {
				case 's':
					secret_key_filename = optarg;
					break;
				case 'p':
					public_key_filename = optarg;
					break;
				case 'r':
					server_public_key_filename = optarg;
					break;
				case 'a':
					server_address = optarg;
					break;
				case 't':
					server_port = optarg;
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

	std::string server_public_key;
	{
		std::fstream server_public_key_file(server_public_key_filename, std::fstream::in);
		if (server_public_key_file.fail()) {
			std::cerr << "Failed to open server public key file" << std::endl;
			return 1;
		}
		server_public_key_file >> server_public_key;
	}

	auto client = CryptoPubClient::FromHostname(server_address, server_port, secret_key, server_public_key);
	client->Loop();
}
