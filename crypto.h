#include <string>

class CryptoBase {
	public:
		static std::string BinToHex(const std::string& bin);
		static void GenKey(std::string* key);
		static void GenKeyPair(std::string* secret_key, std::string* public_key);
};
