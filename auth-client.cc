#include <getopt.h>
#include <stdlib.h>

#include <iostream>

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

	sodium_init();

	SecretKey secret_key;
	secret_key.ReadFromFile(secret_key_filename);

	PublicKey server_public_key;
	server_public_key.ReadFromFile(server_public_key_filename);

	auto client = CryptoPubClient::FromHostname(server_address, server_port, secret_key, server_public_key);
	client->Loop();

	std::cerr << "Shutting down" << std::endl;
}
