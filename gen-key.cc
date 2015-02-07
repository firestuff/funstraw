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
	CryptoUtil::GenKey(&key);

	CryptoUtil::WriteKeyToFile(argv[1], key);

	return 0;
}
