#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/listener.h>

#include <string>

#include "tlv.h"

class CryptoBase {
	public:
		virtual ~CryptoBase() {};

		static void GenKey(std::string* key);
		static void GenKeyPair(std::string* secret_key, std::string* public_key);
		static void DerivePublicKey(const std::string& secret_key, std::string* public_key);
		static void ReadKeyFromFile(const std::string& filename, std::string* key);
		static void WriteKeyToFile(const std::string& filename, const std::string& key);

		static void EncodeEncryptAppend(const std::string& secret_key, const std::string& public_key, const TLVNode& input, TLVNode* container);
		TLVNode *DecryptDecode(const std::string& secret_key, const std::string& public_key, const TLVNode& input);

		std::ostream& Log(void *obj=nullptr);
		std::ostream& LogFatal(void *obj=nullptr);
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
		std::string ephemeral_secret_key_;
		std::string client_public_key_;
		std::string client_ephemeral_public_key_;

		enum {
			AWAITING_HANDSHAKE,
			READY,
		} state_;

		friend CryptoPubServer;
};

class CryptoPubClient : public CryptoBase {
	public:
		CryptoPubClient(struct sockaddr* addr, socklen_t addrlen, const std::string& secret_key, const std::string& server_public_key);
		~CryptoPubClient();

		static CryptoPubClient* FromHostname(const std::string& server_address, const std::string& server_port, const std::string& secret_key, const std::string& server_public_key);

		void Loop();

	private:
		static void OnReadable_(struct bufferevent* bev, void* this__);
		void OnReadable();
		static void OnConnectOrError_(struct bufferevent* bev, const short what, void* this__);
		void OnConnect();
		void OnError();

		struct event_base* event_base_;
		struct bufferevent* bev_;

		const std::string secret_key_;
		const std::string server_public_key_;
		std::string public_key_;
		std::string ephemeral_secret_key_;
		std::string server_ephemeral_public_key_;

		enum {
			AWAITING_HANDSHAKE,
			READY,
		} state_;
};
