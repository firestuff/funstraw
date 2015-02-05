#include <iostream>

#include "nacl/build/instance1/include/amd64/crypto_box.h"

class CryptoBase {
	public:
		static const std::string BinToHex(const std::string& bin) {
			static const char *hex = "0123456789ABCDEF";
			std::string ret;
			ret.reserve(bin.length() * 2);
			for (size_t i = 0; i < bin.length(); i++) {
				const char c = bin[i];
				ret.push_back(hex[(c & 0xf0) >> 4]);
				ret.push_back(hex[c & 0x0f]);
			}
			return ret;
		}
};

int main() {
	std::string pk;
	std::string sk;

	pk = crypto_box_keypair(&sk);

	std::cout << "Secret: " << CryptoBase::BinToHex(sk) << std::endl;
	std::cout << "Public: " << CryptoBase::BinToHex(pk) << std::endl;

	return 0;
}
