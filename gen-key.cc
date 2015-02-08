#include <ctime>
#include <fstream>
#include <iostream>

#include "crypto.h"

int main(int argc, char *argv[]) {
	if (argc < 2) {
		std::cerr << "Usage: " << argv[0] << " key_filename" << std::endl;
		return 1;
	}

	sodium_init();

	SharedKey key;
	CryptoUtil::GenKey(&key);

	key.WriteToFile(argv[1]);

	return 0;
}
