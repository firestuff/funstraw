#include <sys/epoll.h>

#include <string>

class CryptoBase {
	public:
		CryptoBase(const int fd);
		virtual ~CryptoBase();

		static std::string BinToHex(const std::string& bin);
		static void GenKey(std::string* key);
		static void GenKeyPair(std::string* secret_key, std::string* public_key);
		virtual int OnReadable() = 0;

	protected:
		const int fd_;
};

class CryptoPubPeer : public CryptoBase {
	public:
		CryptoPubPeer(const int fd, const std::string secret_key);
		int OnReadable();

	private:
		const std::string secret_key_;
		const std::string ephemeral_secret_key_;
};

class CryptoPubServer : public CryptoBase {
	public:
		CryptoPubServer(const int fd, const std::string secret_key);
		~CryptoPubServer();
		int OnReadable();
		void Loop();

	private:
		const std::string secret_key_;
		const int epoll_fd_;
};
