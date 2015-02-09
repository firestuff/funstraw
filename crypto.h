#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <sodium/core.h>

#include <string>

#include "tlv.h"

class CryptoKey {
	public:
		CryptoKey(const size_t key_bytes);
		~CryptoKey();
		void ReadFromFile(const std::string& filename);
		void WriteToFile(const std::string& filename) const;

		const unsigned char* Key() const;
		bool IsSet() const;

		unsigned char* MutableKey();
		void MarkSet();

		void Clear();

	protected:
		unsigned char* key_;
		bool is_set_;
		const size_t key_bytes_;
};

class SharedKey : public CryptoKey {
	public:
		SharedKey();
};

class SecretKey : public CryptoKey {
	public:
		SecretKey();
};

class PublicKey : public CryptoKey {
	public:
		PublicKey();

		std::string AsString() const;
		std::string ToHex() const;
		void FromString(const std::string& str);
};

class PrecalcKey : public CryptoKey {
	public:
		PrecalcKey();
};

class CryptoUtil {
	public:
		static void GenKey(SharedKey* key);
		static void GenKeyPair(SecretKey* secret_key, PublicKey* public_key);
		static void DerivePublicKey(const SecretKey& secret_key, PublicKey* public_key);
		static void PrecalculateKey(const SecretKey& secret_key, const PublicKey& public_key, PrecalcKey* precalc_key);

		static std::unique_ptr<TLVNode> EncodeEncrypt(const PrecalcKey& precalc_key, const TLVNode& input);
		static std::unique_ptr<TLVNode> DecryptDecode(const PrecalcKey& precalc_key, const TLVNode& input);
};

class CryptoBase {
	protected:
		std::ostream& Log(void *obj=nullptr);
};

class CryptoPubConnBase : public CryptoBase {
	protected:
		CryptoPubConnBase(const SecretKey& secret_key);
		virtual ~CryptoPubConnBase();

		void LogFatal(const std::string& msg, void *obj=nullptr);

		std::unique_ptr<TLVNode> BuildSecureHandshake();
		std::unique_ptr<TLVNode> BuildHandshake();
		void SendHandshake();

		bool HandleSecureHandshake(const TLVNode& node);
		bool HandleHandshake(const TLVNode& node);

		void EncryptSend(const TLVNode& node);

		static void OnReadable_(struct bufferevent* bev, void* this__);
		void OnReadable();
		virtual void OnHandshake(const TLVNode& decoded) = 0;
		virtual bool OnMessage(const TLVNode& node) = 0;

		enum {
			AWAITING_HANDSHAKE,
			READY,
		} state_;

		struct bufferevent* bev_;

		const SecretKey& secret_key_;
		PublicKey public_key_;
		PublicKey peer_public_key_;
		PrecalcKey precalc_key_;

		SecretKey ephemeral_secret_key_;
		PublicKey peer_ephemeral_public_key_;
		PrecalcKey ephemeral_precalc_key_;
};

class CryptoPubServerConnection;

class CryptoPubServer : public CryptoBase {
	public:
		CryptoPubServer(const SecretKey& secret_key);
		~CryptoPubServer();
		void Loop();
		void Shutdown();

	private:
		static void Shutdown_(evutil_socket_t sig, short events, void *this__);

		static void OnNewConn_(struct evconnlistener* listener, int fd, struct sockaddr* client_addr, int client_addrlen, void* this__);
		void OnNewConn(int fd, struct sockaddr* client_addr, int client_addrlen);

		struct event_base* event_base_;
		struct evconnlistener* listener_;
		struct event* sigevent_;

		const SecretKey& secret_key_;
};

class CryptoPubServerConnection : public CryptoPubConnBase {
	public:
		CryptoPubServerConnection(struct bufferevent* bev, const SecretKey& secret_key);
		~CryptoPubServerConnection();

	private:
		void OnHandshake(const TLVNode& decoded);
		bool OnMessage(const TLVNode& node);
		bool OnTunnelRequest(const TLVNode& node);

		static void OnError_(struct bufferevent* bev, const short what, void* this__);
		void OnError(const short what);

		friend CryptoPubServer;
};

class CryptoPubClient : public CryptoPubConnBase {
	public:
		CryptoPubClient(struct sockaddr* addr, socklen_t addrlen, const SecretKey& secret_key, const PublicKey& server_public_key);
		~CryptoPubClient();

		static CryptoPubClient* FromHostname(const std::string& server_address, const std::string& server_port, const SecretKey& secret_key, const PublicKey& server_public_key);

		void Loop();

	private:
		void OnHandshake(const TLVNode& decoded);
		bool OnMessage(const TLVNode& node);

		static void OnConnectOrError_(struct bufferevent* bev, const short what, void* this__);
		void OnConnect();
		void OnError();

		void SendTunnelRequest();

		struct event_base* event_base_;
};
