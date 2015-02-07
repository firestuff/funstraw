#include <getopt.h>

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
	CryptoUtil::ReadKeyFromFile(secret_key_filename, &secret_key);

	CryptoPubServer server(secret_key);
	server.Loop();
}
