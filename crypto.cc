#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <cassert>
#include <fstream>
#include <iostream>

#include <sodium/crypto_box.h>
#include <sodium/crypto_secretbox.h>
#include <sodium/crypto_scalarmult.h>
#include <sodium/randombytes.h>
#include <sodium/utils.h>

#include "crypto.h"


#define TLV_TYPE_ENCRYPTED_BLOB          0x0000
#define TLV_TYPE_NONCE                   0x0001
#define TLV_TYPE_PUBLIC_KEY              0x0002
#define TLV_TYPE_DOWNSTREAM_BITRATE      0x0003

#define TLV_TYPE_ENCRYPTED               0x8000
#define TLV_TYPE_HANDSHAKE               0x8001
#define TLV_TYPE_HANDSHAKE_SECURE        0x8002
#define TLV_TYPE_TUNNEL_REQUEST          0x8003
#define TLV_TYPE_CHANNEL                 0x8004


void CryptoUtil::GenKey(SharedKey* key) {
	randombytes_buf(key->MutableKey(), crypto_secretbox_KEYBYTES);
	key->MarkSet();
}

void CryptoUtil::GenKeyPair(SecretKey* secret_key, PublicKey* public_key) {
	assert(!crypto_box_keypair(public_key->MutableKey(), secret_key->MutableKey()));
	public_key->MarkSet();
	secret_key->MarkSet();
}

void CryptoUtil::DerivePublicKey(const SecretKey& secret_key, PublicKey* public_key) {
	assert(!crypto_scalarmult_base(public_key->MutableKey(), secret_key.Key()));
	public_key->MarkSet();
}

std::unique_ptr<TLVNode> CryptoUtil::EncodeEncrypt(const SecretKey& secret_key, const PublicKey& public_key, const TLVNode& input) {
	std::string encoded;
	input.Encode(&encoded);

	size_t encrypted_bytes = encoded.length() + crypto_box_MACBYTES;

	unsigned char nonce[crypto_box_NONCEBYTES];
	randombytes_buf(nonce, crypto_box_NONCEBYTES);

	unsigned char output[encrypted_bytes];
	assert(!crypto_box_easy(output, (const unsigned char*)encoded.data(), encoded.length(), nonce, public_key.Key(), secret_key.Key()));

	std::unique_ptr<TLVNode> encrypted(new TLVNode(TLV_TYPE_ENCRYPTED));
	encrypted->AppendChild(new TLVNode(TLV_TYPE_NONCE, std::string((char*)nonce, crypto_box_NONCEBYTES)));
	encrypted->AppendChild(new TLVNode(TLV_TYPE_ENCRYPTED_BLOB, std::string((char*)output, encrypted_bytes)));

	return encrypted;
}

std::unique_ptr<TLVNode> CryptoUtil::DecryptDecode(const SecretKey& secret_key, const PublicKey& public_key, const TLVNode& input) {
	assert(input.GetType() == TLV_TYPE_ENCRYPTED);

	auto nonce = input.FindChild(TLV_TYPE_NONCE);
	if (!nonce || nonce->GetValue().length() != crypto_box_NONCEBYTES) {
		return nullptr;
	}
	auto encrypted = input.FindChild(TLV_TYPE_ENCRYPTED_BLOB);
	if (!encrypted || encrypted->GetValue().length() < crypto_box_MACBYTES) {
		return nullptr;
	}

	size_t decrypted_bytes = encrypted->GetValue().length() - crypto_box_MACBYTES;

	unsigned char output[decrypted_bytes];
	if (crypto_box_open_easy(output, (const unsigned char*)encrypted->GetValue().data(), encrypted->GetValue().length(), (const unsigned char*)nonce->GetValue().data(), public_key.Key(), secret_key.Key())) {
		return nullptr;
	}

	return TLVNode::Decode(std::string((char*)output, decrypted_bytes));
}


CryptoKey::CryptoKey(const size_t key_bytes)
	: key_bytes_(key_bytes),
    is_set_(false),
    key_((unsigned char*)sodium_malloc(key_bytes)) {
	assert(key_);
}

CryptoKey::~CryptoKey() {
	sodium_free(key_);
}

void CryptoKey::WriteToFile(const std::string& filename) const {
	assert(is_set_);
	int fd = open(filename.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0400);
	assert(fd != -1);
	assert(write(fd, key_, key_bytes_) == key_bytes_);
	assert(!close(fd));
}

void CryptoKey::ReadFromFile(const std::string& filename) {
	assert(!is_set_);
	int fd = open(filename.c_str(), O_RDONLY);
	assert(fd != -1);
	assert(read(fd, key_, key_bytes_ + 1) == key_bytes_);
	assert(!close(fd));
	MarkSet();
}

const unsigned char* CryptoKey::Key() const {
	assert(is_set_);
	return key_;
}

bool CryptoKey::IsSet() const {
	return is_set_;
}

unsigned char* CryptoKey::MutableKey() {
	assert(!is_set_);
	return key_;
}

void CryptoKey::MarkSet() {
	assert(!is_set_);
	is_set_ = true;
	assert(!sodium_mprotect_readonly(key_));
}


SharedKey::SharedKey()
	: CryptoKey(crypto_secretbox_KEYBYTES) {}


SecretKey::SecretKey()
	: CryptoKey(crypto_box_SECRETKEYBYTES) {}


PublicKey::PublicKey()
	: CryptoKey(crypto_box_PUBLICKEYBYTES) {}

std::string PublicKey::AsString() const {
	assert(is_set_);
	return std::string((char*)key_, key_bytes_);
}

std::string PublicKey::ToHex() const {
	static const char hex[] = "0123456789abcdef";
	std::string ret;
	ret.reserve(key_bytes_ * 2);
	for (int i = 0; i < key_bytes_; i++) {
		ret.push_back(hex[(key_[i] & 0xf0) >> 4]);
		ret.push_back(hex[key_[i] & 0x0f]);
	}
	return ret;
}

void PublicKey::FromString(const std::string& str) {
	assert(!is_set_);
	assert(str.length() == key_bytes_);
	memcpy(key_, str.data(), key_bytes_);
	MarkSet();
}


std::ostream& CryptoBase::Log(void *obj) {
	char buf[64];
	snprintf(buf, 64, "[%p] ", obj ? obj : this);
	return std::cerr << buf;
}


CryptoPubConnBase::CryptoPubConnBase(const SecretKey& secret_key)
	: secret_key_(secret_key),
	  state_(AWAITING_HANDSHAKE) {}

CryptoPubConnBase::~CryptoPubConnBase() {
	bufferevent_free(bev_);
}

void CryptoPubConnBase::LogFatal(const std::string& msg, void *obj) {
	Log(obj) << msg << std::endl;
	delete this;
	return;
}

std::unique_ptr<TLVNode> CryptoPubConnBase::BuildSecureHandshake() {
	PublicKey ephemeral_public_key;
	CryptoUtil::GenKeyPair(&ephemeral_secret_key_, &ephemeral_public_key);

	TLVNode secure_handshake(TLV_TYPE_HANDSHAKE_SECURE);
	secure_handshake.AppendChild(new TLVNode(TLV_TYPE_PUBLIC_KEY, ephemeral_public_key.AsString()));
	return CryptoUtil::EncodeEncrypt(secret_key_, peer_public_key_, secure_handshake);
}

std::unique_ptr<TLVNode> CryptoPubConnBase::BuildHandshake() {
	auto secure_handshake = BuildSecureHandshake();

	std::unique_ptr<TLVNode> handshake(new TLVNode(TLV_TYPE_HANDSHAKE));
	PublicKey public_key;
	CryptoUtil::DerivePublicKey(secret_key_, &public_key);
	handshake->AppendChild(new TLVNode(TLV_TYPE_PUBLIC_KEY, public_key.AsString()));
	handshake->AppendChild(secure_handshake.release());

	return handshake;
}

void CryptoPubConnBase::SendHandshake() {
	auto handshake = BuildHandshake();
	std::string out;
	handshake->Encode(&out);
	bufferevent_write(bev_, out.data(), out.length());
}

bool CryptoPubConnBase::HandleSecureHandshake(const TLVNode& node) {
	assert(node.GetType() == TLV_TYPE_ENCRYPTED);

	std::unique_ptr<TLVNode> decrypted(CryptoUtil::DecryptDecode(secret_key_, peer_public_key_, node));
	if (!decrypted.get()) {
		LogFatal("Protocol error (handshake; decryption failure)");
		return false;
	}

	auto peer_ephemeral_public_key = decrypted->FindChild(TLV_TYPE_PUBLIC_KEY);
	if (!peer_ephemeral_public_key) {
		LogFatal("Protocol error (handshake; no ephemeral public key)");
		return false;
	}
	if (peer_ephemeral_public_key->GetValue().length() != crypto_box_PUBLICKEYBYTES) {
		LogFatal("Protocol error (handshake; wrong ephemeral public key length)");
		return false;
	}
	peer_ephemeral_public_key_.FromString(peer_ephemeral_public_key->GetValue());
	return true;
}

bool CryptoPubConnBase::HandleHandshake(const TLVNode& node) {
	if (node.GetType() != TLV_TYPE_HANDSHAKE) {
		LogFatal("Protocol error (handshake; wrong message type)");
		return false;
	}

	auto peer_public_key = node.FindChild(TLV_TYPE_PUBLIC_KEY);
	if (!peer_public_key) {
		LogFatal("Protocol error (handshake; no public key)");
		return false;
	}
	if (peer_public_key->GetValue().length() != crypto_box_PUBLICKEYBYTES) {
		LogFatal("Protocol error (handshake; wrong public key length)");
		return false;
	}
	if (peer_public_key_.IsSet()) {
		// We're the client and already know the server public key; we expect these to match.
		// Eventually, we can do smarter things here to allow key rotation.
		if (peer_public_key_.AsString() != peer_public_key->GetValue()) {
			LogFatal("Protocol error (handshake; public key mismatch)");
			return false;
		}
	} else {
		peer_public_key_.FromString(peer_public_key->GetValue());
	}
	auto encrypted = node.FindChild(TLV_TYPE_ENCRYPTED);
	if (!encrypted) {
		LogFatal("Protocol error (handshake; no encrypted portion)");
		return false;
	}

	return HandleSecureHandshake(*encrypted);
}

void CryptoPubConnBase::EncryptSend(const TLVNode& node) {
	auto encrypted = CryptoUtil::EncodeEncrypt(ephemeral_secret_key_, peer_ephemeral_public_key_, node);
	std::string out;
	encrypted->Encode(&out);
	bufferevent_write(bev_, out.data(), out.length());
}

void CryptoPubConnBase::OnReadable_(struct bufferevent* bev, void* this__) {
	auto this_ = (CryptoPubConnBase*)this__;
	this_->OnReadable();
}

void CryptoPubConnBase::OnReadable() {
	char buf[UINT16_MAX];
	int bytes = bufferevent_read(bev_, buf, UINT16_MAX);
	const std::string input(buf, bytes);
	std::unique_ptr<TLVNode> decoded(TLVNode::Decode(input));

	if (!decoded.get()) {
		// TODO: re-buffer?
		return;
	}

	if (state_ == AWAITING_HANDSHAKE) {
		OnHandshake(*decoded);
		return;
	}

	if (decoded->GetType() != TLV_TYPE_ENCRYPTED) {
		LogFatal("Protocol error (wrong message type)");
		return;
	}

	std::unique_ptr<TLVNode> decrypted(CryptoUtil::DecryptDecode(ephemeral_secret_key_, peer_ephemeral_public_key_, *decoded));
	if (!decrypted.get()) {
		LogFatal("Protocol error (decryption failure)");
		return;
	}

	if (!OnMessage(*decrypted)) {
		LogFatal("Protocol error (message handling)");
		return;
	}
}


CryptoPubServer::CryptoPubServer(const SecretKey& secret_key)
	: secret_key_(secret_key),
	  event_base_(event_base_new()) {
	sigevent_ = evsignal_new(event_base_, SIGINT, &CryptoPubServer::Shutdown_, this);
	event_add(sigevent_, NULL);

	struct sockaddr_in6 server_addr = {0};
	server_addr.sin6_family = AF_INET6;
	server_addr.sin6_addr = in6addr_any;
	server_addr.sin6_port = htons(4990);

	listener_ = evconnlistener_new_bind(event_base_, &CryptoPubServer::OnNewConn_, this, LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_FREE, -1, (struct sockaddr*)&server_addr, sizeof(server_addr));
}

CryptoPubServer::~CryptoPubServer() {
	event_free(sigevent_);
	evconnlistener_free(listener_);
	event_base_free(event_base_);
}

void CryptoPubServer::OnNewConn_(struct evconnlistener* listener, int client_fd, struct sockaddr* client_addr_, int client_addrlen, void* this__) {
	auto this_ = (CryptoPubServer*)this__;
	this_->OnNewConn(client_fd, client_addr_, client_addrlen);
}

void CryptoPubServer::OnNewConn(int client_fd, struct sockaddr* client_addr_, int client_addrlen) {
	assert(client_addr_->sa_family == AF_INET6);
	auto client_addr = (struct sockaddr_in6*)client_addr_;

	char buf[128];
	inet_ntop(AF_INET6, &client_addr->sin6_addr, buf, 128);

	auto bev = bufferevent_socket_new(this->event_base_, client_fd, BEV_OPT_CLOSE_ON_FREE);
	bufferevent_enable(bev, EV_READ);
	bufferevent_enable(bev, EV_WRITE);
	auto peer = new CryptoPubServerConnection(bev, this->secret_key_);
	bufferevent_setcb(bev, &CryptoPubServerConnection::OnReadable_, NULL, &CryptoPubServerConnection::OnError_, peer);

	Log(peer) << "New connection from [" << buf << "]:" << ntohs(client_addr->sin6_port) << std::endl;
}

void CryptoPubServer::Loop() {
	event_base_dispatch(event_base_);
}

void CryptoPubServer::Shutdown_(evutil_socket_t sig, short events, void *this__) {
	auto this_ = (CryptoPubServer*)this__;
	this_->Shutdown();
}

void CryptoPubServer::Shutdown() {
	event_base_loopexit(event_base_, NULL);
}


CryptoPubServerConnection::CryptoPubServerConnection(struct bufferevent* bev, const SecretKey& secret_key)
	: CryptoPubConnBase(secret_key) {
	bev_ = bev;
}

CryptoPubServerConnection::~CryptoPubServerConnection() {
	Log() << "Connection closed" << std::endl;
}

void CryptoPubServerConnection::OnHandshake(const TLVNode& decoded) {
	if (!HandleHandshake(decoded)) {
		return;
	}

	SendHandshake();

	this->state_ = READY;
	Log() << "Handshake successful (client ID: " << peer_public_key_.ToHex() << ")" << std::endl;
}

bool CryptoPubServerConnection::OnMessage(const TLVNode& message) {
	switch (message.GetType()) {
		case TLV_TYPE_TUNNEL_REQUEST:
			return OnTunnelRequest(message);
		default:
			return false;
	}
}

bool CryptoPubServerConnection::OnTunnelRequest(const TLVNode& message) {
	Log() << "New tunnel request" << std::endl;
	for (auto child : message.GetChildren()) {
		if (child->GetType() != TLV_TYPE_CHANNEL) {
			continue;
		}
		Log() << "Channel" << std::endl;
	}
	return true;
}

void CryptoPubServerConnection::OnError_(struct bufferevent* bev, const short what, void* this__) {
	auto this_ = (CryptoPubServerConnection*)this__;
	this_->OnError(what);
}

void CryptoPubServerConnection::OnError(const short what) {
	delete this;
}


CryptoPubClient::CryptoPubClient(struct sockaddr* addr, socklen_t addrlen, const SecretKey& secret_key, const PublicKey& server_public_key, const std::list<uint32_t>& channel_bitrates)
	: CryptoPubConnBase(secret_key),
	  event_base_(event_base_new()),
		channel_bitrates_(channel_bitrates) {
	bev_ = bufferevent_socket_new(event_base_, -1, BEV_OPT_CLOSE_ON_FREE);
	peer_public_key_.FromString(server_public_key.AsString());

	bufferevent_setcb(bev_, &CryptoPubClient::OnReadable_, NULL, &CryptoPubClient::OnConnectOrError_, this);
	bufferevent_enable(bev_, EV_READ);
	bufferevent_enable(bev_, EV_WRITE);
	bufferevent_socket_connect(bev_, addr, addrlen);
}

CryptoPubClient::~CryptoPubClient() {
	event_base_free(event_base_);
}

CryptoPubClient* CryptoPubClient::FromHostname(const std::string& server_address, const std::string& server_port, const SecretKey& secret_key, const PublicKey& server_public_key, const std::list<uint32_t>& channel_bitrates) {
	struct addrinfo* res;
	int gai_ret = getaddrinfo(server_address.c_str(), server_port.c_str(), NULL, &res);
	if (gai_ret) {
		std::cerr << "Failed to resolve server_address: " << gai_strerror(gai_ret) << std::endl;
		return nullptr;
	}
	auto ret = new CryptoPubClient((struct sockaddr*)res->ai_addr, res->ai_addrlen, secret_key, server_public_key, channel_bitrates);
	freeaddrinfo(res);
	return ret;
}

void CryptoPubClient::OnHandshake(const TLVNode& decoded) {
	if (!HandleHandshake(decoded)) {
		return;
	}

	this->state_ = READY;
	Log() << "Handshake successful" << std::endl;

	SendTunnelRequest();
}

bool CryptoPubClient::OnMessage(const TLVNode& message) {
	switch (message.GetType()) {
		default:
			return false;
	}
}

void CryptoPubClient::OnConnectOrError_(struct bufferevent* bev, const short what, void* this__) {
	auto this_ = (CryptoPubClient*)this__;
	if (what == BEV_EVENT_CONNECTED) {
		this_->OnConnect();
	} else {
		this_->OnError();
	}
}

void CryptoPubClient::OnConnect() {
	Log() << "Connected to server" << std::endl;
	SendHandshake();
}

void CryptoPubClient::SendTunnelRequest() {
	TLVNode tunnel_request(TLV_TYPE_TUNNEL_REQUEST);
	for (auto channel_bitrate : channel_bitrates_) {
		auto channel = new TLVNode(TLV_TYPE_CHANNEL);
		channel_bitrate = htonl(channel_bitrate);
		channel->AppendChild(new TLVNode(TLV_TYPE_DOWNSTREAM_BITRATE, std::string((char*)&channel_bitrate, sizeof(channel_bitrate))));
		tunnel_request.AppendChild(channel);
	}
	EncryptSend(tunnel_request);
}

void CryptoPubClient::OnError() {
	Log() << "Connection error" << std::endl;
}

void CryptoPubClient::Loop() {
	event_base_dispatch(event_base_);
}
