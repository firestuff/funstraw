#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/listener.h>

#include <string>

class CryptoBase {
	public:
		virtual ~CryptoBase() {};

		static void GenKey(std::string* key);
		static void GenKeyPair(std::string* secret_key, std::string* public_key);
};

class CryptoPubServerConnection : public CryptoBase {
	public:
		CryptoPubServerConnection(struct bufferevent* bev, const std::string secret_key);
		~CryptoPubServerConnection();
		static void OnReadable(struct bufferevent* bev, void* this__);
		static void OnError(struct bufferevent* bev, const short what, void* this__);

	private:
		struct bufferevent* bev_;

		const std::string secret_key_;
		const std::string ephemeral_secret_key_;
		const std::string client_public_key_;
		enum {
			AWAITING_HANDSHAKE,
			READY,
		} state_;
};

class CryptoPubServer : public CryptoBase {
	public:
		CryptoPubServer(const std::string secret_key);
		~CryptoPubServer();
		static void OnNewConn(struct evconnlistener* listener, int fd, struct sockaddr* client_addr, int client_addrlen, void* this__);
		void Loop();

	private:
		struct event_base *event_base_;
		struct evconnlistener *listener_;

		const std::string secret_key_;
};
