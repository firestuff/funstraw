#include <ctime>
#include <fstream>
#include <iostream>

#include "crypto.h"

int main(int argc, char *argv[]) {
	if (argc < 3) {
		std::cerr << "Usage: " << argv[0] << " secret_key_filename public_key_filename" << std::endl;
		return 1;
	}

	std::string secret_key, public_key;
	CryptoBase::GenKeyPair(&secret_key, &public_key);

	{
		std::fstream secret_key_file(argv[1], std::fstream::out);
		if (secret_key_file.fail()) {
			std::cerr << "Failed to open secret key file" << std::endl;
			return 1;
		}
		secret_key_file << "# Secret key" << std::endl;
		secret_key_file << CryptoBase::BinToHex(secret_key) << std::endl;
	}

	{
		std::fstream public_key_file(argv[2], std::fstream::out);
		if (public_key_file.fail()) {
			std::cerr << "Failed to open public key file" << std::endl;
			return 1;
		}
		public_key_file << "# Public key" << std::endl;
		public_key_file << CryptoBase::BinToHex(public_key) << std::endl;
	}

	return 0;
}
