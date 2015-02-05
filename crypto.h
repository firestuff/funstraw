#include <string>

class CryptoBase {
	public:
		static std::string BinToHex(const std::string& bin);
		static void GenKeyPair(std::string* sk, std::string* pk);
};
