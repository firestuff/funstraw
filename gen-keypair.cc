#include <ctime>
#include <fstream>
#include <iostream>

#include "crypto.h"

int main(int argc, char *argv[]) {
	if (argc < 3) {
		std::cerr << "Usage: " << argv[0] << " secret_filename public_filename" << std::endl;
		return 1;
	}

	std::string pk;
	std::string sk;
	CryptoBase::GenKeyPair(&sk, &pk);

	{
		std::fstream skf(argv[1], std::fstream::out);
		if (skf.fail()) {
			std::cerr << "Failed to open secret key file" << std::endl;
			return 1;
		}
		skf << "# Secret key" << std::endl;
		skf << CryptoBase::BinToHex(sk) << std::endl;
	}

	{
		std::fstream pkf(argv[2], std::fstream::out);
		if (pkf.fail()) {
			std::cerr << "Failed to open public key file" << std::endl;
			return 1;
		}
		pkf << "# Public key" << std::endl;
		pkf << CryptoBase::BinToHex(pk) << std::endl;
	}

	return 0;
}
