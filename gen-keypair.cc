#include <ctime>
#include <fstream>
#include <iostream>

#include "crypto.h"

int main(int argc, char *argv[]) {
	if (argc < 3) {
		std::cerr << "Usage: " << argv[0] << " secret_key_filename public_key_filename" << std::endl;
		return 1;
	}

	SecretKey secret_key;
	PublicKey public_key;
	CryptoUtil::GenKeyPair(&secret_key, &public_key);

	secret_key.WriteToFile(argv[1]);
	public_key.WriteToFile(argv[2]);

	return 0;
}
