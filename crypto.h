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

class CryptoPubServerConnection;

class CryptoPubServer : public CryptoBase {
	public:
		CryptoPubServer(const std::string& secret_key);
		~CryptoPubServer();
		void Loop();

	private:
		static void OnNewConn_(struct evconnlistener* listener, int fd, struct sockaddr* client_addr, int client_addrlen, void* this__);
		void OnNewConn(int fd, struct sockaddr* client_addr, int client_addrlen);

		struct event_base* event_base_;
		struct evconnlistener* listener_;

		const std::string secret_key_;
};

class CryptoPubServerConnection : public CryptoBase {
	public:
		CryptoPubServerConnection(struct bufferevent* bev, const std::string& secret_key);
		~CryptoPubServerConnection();

	private:
		static void OnReadable_(struct bufferevent* bev, void* this__);
		void OnReadable();
		static void OnError_(struct bufferevent* bev, const short what, void* this__);
		void OnError(const short what);

		struct bufferevent* bev_;

		const std::string secret_key_;
		const std::string ephemeral_secret_key_;
		const std::string client_public_key_;
		enum {
			AWAITING_HANDSHAKE,
			READY,
		} state_;

		friend CryptoPubServer;
};

class CryptoPubClient : public CryptoBase {
	public:
		CryptoPubClient(struct sockaddr* addr, socklen_t addrlen);
		~CryptoPubClient();

		static CryptoPubClient* FromHostname(const std::string& server_address, const std::string& server_port);

		void Loop();

	private:
		struct event_base* event_base_;
		struct bufferevent* bev_;
};
