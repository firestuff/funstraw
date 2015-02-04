#include <iostream>

#include "nacl/build/instance1/include/amd64/crypto_box.h"

int main() {
	std::string pk;
	std::string sk;

	pk = crypto_box_keypair(&sk);

	std::cout << pk.size() << std::endl;

	return 0;
}
