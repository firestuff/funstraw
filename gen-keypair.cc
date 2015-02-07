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

	CryptoBase::WriteKeyToFile(argv[1], secret_key);
	CryptoBase::WriteKeyToFile(argv[2], public_key);

	return 0;
}
