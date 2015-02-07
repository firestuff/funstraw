#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/listener.h>

#include <string>

#include "tlv.h"

class CryptoUtil {
	public:
		static std::string BinToHex(const std::string& bin);

		static void GenKey(std::string* key);
		static void GenKeyPair(std::string* secret_key, std::string* public_key);
		static void DerivePublicKey(const std::string& secret_key, std::string* public_key);
		static void ReadKeyFromFile(const std::string& filename, std::string* key);
		static void WriteKeyToFile(const std::string& filename, const std::string& key);

		static std::unique_ptr<TLVNode> EncodeEncrypt(const std::string& secret_key, const std::string& public_key, const TLVNode& input);
		static std::unique_ptr<TLVNode> DecryptDecode(const std::string& secret_key, const std::string& public_key, const TLVNode& input);
};

class CryptoBase {
	public:
		std::ostream& Log(void *obj=nullptr);
		std::ostream& LogFatal(void *obj=nullptr);
};

class CryptoConnBase : public CryptoBase {
	protected:
		CryptoConnBase(const std::string& secret_key);

		std::unique_ptr<TLVNode> BuildSecureHandshake();
		bool HandleSecureHandshake(const TLVNode& node);

		static void OnReadable_(struct bufferevent* bev, void* this__);
		void OnReadable();
		virtual void OnHandshake(const TLVNode& decoded) = 0;
		virtual bool OnMessage(const TLVNode& node) = 0;

		enum {
			AWAITING_HANDSHAKE,
			READY,
		} state_;

		struct bufferevent* bev_;

		const std::string secret_key_;
		std::string peer_public_key_;
		std::string ephemeral_secret_key_;
		std::string peer_ephemeral_public_key_;
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

class CryptoPubServerConnection : public CryptoConnBase {
	public:
		CryptoPubServerConnection(struct bufferevent* bev, const std::string& secret_key);
		~CryptoPubServerConnection();

	private:
		void OnHandshake(const TLVNode& decoded);
		bool OnMessage(const TLVNode& node);

		static void OnError_(struct bufferevent* bev, const short what, void* this__);
		void OnError(const short what);

		void SendHandshake();

		friend CryptoPubServer;
};

class CryptoPubClient : public CryptoConnBase {
	public:
		CryptoPubClient(struct sockaddr* addr, socklen_t addrlen, const std::string& secret_key, const std::string& server_public_key, const std::list<uint64_t>& channel_bitrates);
		~CryptoPubClient();

		static CryptoPubClient* FromHostname(const std::string& server_address, const std::string& server_port, const std::string& secret_key, const std::string& server_public_key, const std::list<uint64_t>& channel_bitrates);

		void Loop();

	private:
		void OnHandshake(const TLVNode& decoded);
		bool OnMessage(const TLVNode& node);

		static void OnConnectOrError_(struct bufferevent* bev, const short what, void* this__);
		void OnConnect();
		void OnError();

		void SendHandshake();
		void SendTunnelRequest();

		struct event_base* event_base_;

		const std::list<uint64_t> channel_bitrates_;
};
