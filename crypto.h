#include <sys/epoll.h>

#include <string>

class CryptoBase {
	public:
		CryptoBase(const int fd);
		virtual ~CryptoBase();

		static void GenKey(std::string* key);
		static void GenKeyPair(std::string* secret_key, std::string* public_key);
		virtual void OnReadable() = 0;

	protected:
		const int fd_;
};

class CryptoPubServerConnection : public CryptoBase {
	public:
		CryptoPubServerConnection(const int fd, const std::string secret_key);
		void OnReadable();

	private:
		const std::string secret_key_;
		const std::string ephemeral_secret_key_;
};

class CryptoPubServer : public CryptoBase {
	public:
		CryptoPubServer(const int fd, const std::string secret_key);
		~CryptoPubServer();
		void OnReadable();
		void Loop();

	private:
		const std::string secret_key_;
		const int epoll_fd_;
};
