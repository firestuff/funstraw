#include <ctime>
#include <fstream>
#include <iostream>

#include "crypto.h"

int main(int argc, char *argv[]) {
	if (argc < 2) {
		std::cerr << "Usage: " << argv[0] << " key_filename" << std::endl;
		return 1;
	}

	std::string key;
	CryptoBase::GenKey(&key);

	{
		std::fstream key_file(argv[1], std::fstream::out);
		if (key_file.fail()) {
			std::cerr << "Failed to open key file" << std::endl;
			return 1;
		}
		key_file << key;
	}

	return 0;
}
