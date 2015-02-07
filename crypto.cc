#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <unistd.h>

#include <cassert>
#include <fstream>
#include <iostream>

#include <sodium/crypto_box.h>
#include <sodium/crypto_secretbox.h>
#include <sodium/crypto_scalarmult.h>
#include <sodium/randombytes.h>

#include "crypto.h"


#define TLV_TYPE_ENCRYPTED_BLOB          0x0000
#define TLV_TYPE_NONCE                   0x0001
#define TLV_TYPE_PUBLIC_KEY              0x0002

#define TLV_TYPE_ENCRYPTED               0x8000
#define TLV_TYPE_CLIENT_HANDSHAKE        0x8001
#define TLV_TYPE_CLIENT_HANDSHAKE_SECURE 0x8002
#define TLV_TYPE_SERVER_HANDSHAKE        0x8001
#define TLV_TYPE_SERVER_HANDSHAKE_SECURE 0x8002


std::string CryptoBase::BinToHex(const std::string& bin) {
	static const char hex[] = "0123456789abcdef";
	std::string ret;
	ret.reserve(bin.length() * 2);
	for (int i = 0; i < bin.length(); i++) {
		ret.push_back(hex[(bin[i] & 0xf0) >> 4]);
		ret.push_back(hex[bin[i] & 0x0f]);
	}
	return ret;
}

void CryptoBase::GenKey(std::string* key) {
	unsigned char buf[crypto_secretbox_KEYBYTES];
	randombytes_buf(buf, crypto_secretbox_KEYBYTES);
	key->assign((char*)buf, crypto_secretbox_KEYBYTES);
}

void CryptoBase::GenKeyPair(std::string* secret_key, std::string* public_key) {
	unsigned char public_key_buf[crypto_box_PUBLICKEYBYTES];
	unsigned char secret_key_buf[crypto_box_PUBLICKEYBYTES];
	assert(crypto_box_keypair(public_key_buf, secret_key_buf) == 0);
	public_key->assign((char*)public_key_buf, crypto_box_PUBLICKEYBYTES);
	secret_key->assign((char*)secret_key_buf, crypto_box_SECRETKEYBYTES);
}

void CryptoBase::DerivePublicKey(const std::string& secret_key, std::string* public_key) {
	assert(secret_key.length() == crypto_box_SECRETKEYBYTES);
	unsigned char buf[crypto_box_PUBLICKEYBYTES];
	assert(!crypto_scalarmult_base(buf, (const unsigned char*)secret_key.data()));
	public_key->assign((char*)buf, crypto_box_PUBLICKEYBYTES);
}

void CryptoBase::ReadKeyFromFile(const std::string& filename, std::string* key) {
	std::fstream key_file(filename, std::fstream::in);
	assert(!key_file.fail());
	key_file >> *key;
}

void CryptoBase::WriteKeyToFile(const std::string& filename, const std::string& key) {
	std::fstream key_file(filename, std::fstream::out);
	assert(!key_file.fail());
	key_file << key;
}

void CryptoBase::EncodeEncryptAppend(const std::string& secret_key, const std::string& public_key, const TLVNode& input, TLVNode* container) {
	assert(secret_key.length() == crypto_box_SECRETKEYBYTES);
	assert(public_key.length() == crypto_box_PUBLICKEYBYTES);

	std::string encoded;
	input.Encode(&encoded);

	size_t encrypted_bytes = encoded.length() + crypto_box_MACBYTES;

	unsigned char nonce[crypto_box_NONCEBYTES];
	randombytes_buf(nonce, crypto_box_NONCEBYTES);

	unsigned char output[encrypted_bytes];
	assert(!crypto_box_easy(output, (const unsigned char*)encoded.data(), encoded.length(), nonce, (const unsigned char*)public_key.data(), (const unsigned char*)secret_key.data()));

	auto encrypted = new TLVNode(TLV_TYPE_ENCRYPTED);
	encrypted->AppendChild(new TLVNode(TLV_TYPE_NONCE, std::string((char*)nonce, crypto_box_NONCEBYTES)));
	encrypted->AppendChild(new TLVNode(TLV_TYPE_ENCRYPTED_BLOB, std::string((char*)output, encrypted_bytes)));

	container->AppendChild(encrypted);
}

TLVNode* CryptoBase::DecryptDecode(const std::string& secret_key, const std::string& public_key, const TLVNode& input) {
	assert(secret_key.length() == crypto_box_SECRETKEYBYTES);
	assert(public_key.length() == crypto_box_PUBLICKEYBYTES);
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
	if (crypto_box_open_easy(output, (const unsigned char*)encrypted->GetValue().data(), encrypted->GetValue().length(), (const unsigned char*)nonce->GetValue().data(), (const unsigned char*)public_key.data(), (const unsigned char*)secret_key.data())) {
		Log() << "Decryption failure" << std::endl;
		return nullptr;
	}

	return TLVNode::Decode(std::string((char*)output, decrypted_bytes));
}

std::ostream& CryptoBase::Log(void *obj) {
	char buf[64];
	snprintf(buf, 64, "[%p] ", obj ? obj : this);
	return std::cerr << buf;
}

std::ostream& CryptoBase::LogFatal(void *obj) {
	std::ostream& ret = Log(obj);
	delete this;
	return ret;
}


CryptoPubServer::CryptoPubServer(const std::string& secret_key)
	: secret_key_(secret_key),
	  event_base_(event_base_new()) {
	assert(secret_key_.length() == crypto_box_SECRETKEYBYTES);

	struct sockaddr_in6 server_addr = {0};
	server_addr.sin6_family = AF_INET6;
	server_addr.sin6_addr = in6addr_any;
	server_addr.sin6_port = htons(4990);

	listener_ = evconnlistener_new_bind(event_base_, &CryptoPubServer::OnNewConn_, this, LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_FREE, -1, (struct sockaddr*)&server_addr, sizeof(server_addr));
}

CryptoPubServer::~CryptoPubServer() {
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


CryptoPubServerConnection::CryptoPubServerConnection(struct bufferevent* bev, const std::string& secret_key)
	: bev_(bev),
	  secret_key_(secret_key),
    state_(AWAITING_HANDSHAKE) {
}

CryptoPubServerConnection::~CryptoPubServerConnection() {
	Log() << "Connection closed" << std::endl;
	bufferevent_free(bev_);
}

void CryptoPubServerConnection::OnReadable_(struct bufferevent* bev, void* this__) {
	auto this_ = (CryptoPubServerConnection*)this__;
	this_->OnReadable();
}

void CryptoPubServerConnection::OnReadable() {
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
		LogFatal() << "Protocol error (unexpected message type)" << std::endl;
		return;
	}

  std::unique_ptr<TLVNode> decrypted(DecryptDecode(ephemeral_secret_key_, client_ephemeral_public_key_, *decoded));
	if (!decrypted.get()) {
		LogFatal() << "Protocol error (decryption failure)" << std::endl;
		return;
	}

	switch (decrypted->GetType()) {
	}
}

void CryptoPubServerConnection::OnHandshake(const TLVNode& decoded) {
	auto client_public_key = decoded.FindChild(TLV_TYPE_PUBLIC_KEY);
	if (!client_public_key) {
		LogFatal() << "Protocol error (client handshake -- no public key)" << std::endl;
		return;
	}
	client_public_key_ = client_public_key->GetValue();
	if (client_public_key_.length() != crypto_box_PUBLICKEYBYTES) {
		LogFatal() << "Protocol error (client handshake -- wrong public key length)" << std::endl;
		return;
	}
	auto encrypted = decoded.FindChild(TLV_TYPE_ENCRYPTED);
	if (!encrypted) {
		LogFatal() << "Protocol error (client handshake -- no encrypted portion)" << std::endl;
		return;
	}

	std::unique_ptr<TLVNode> decrypted(DecryptDecode(secret_key_, client_public_key->GetValue(), *encrypted));
	if (!decrypted.get()) {
		LogFatal() << "Protocol error (client handshake -- decryption failure)" << std::endl;
		return;
	}

	auto client_ephemeral_public_key = decrypted->FindChild(TLV_TYPE_PUBLIC_KEY);
	if (!client_ephemeral_public_key) {
		LogFatal() << "Protocol error (client handshake -- no ephemeral public key)" << std::endl;
		return;
	}
	client_ephemeral_public_key_ = client_ephemeral_public_key->GetValue();
	if (client_ephemeral_public_key_.length() != crypto_box_PUBLICKEYBYTES) {
		LogFatal() << "Protocol error (client handshake -- wrong ephemeral public key length)" << std::endl;
		return;
	}

	std::string ephemeral_public_key;
	GenKeyPair(&ephemeral_secret_key_, &ephemeral_public_key);

	TLVNode handshake(TLV_TYPE_SERVER_HANDSHAKE);
	TLVNode secure_handshake(TLV_TYPE_SERVER_HANDSHAKE_SECURE);
	secure_handshake.AppendChild(new TLVNode(TLV_TYPE_PUBLIC_KEY, ephemeral_public_key));
	EncodeEncryptAppend(secret_key_, client_public_key_, secure_handshake, &handshake);

	std::string out;
	handshake.Encode(&out);
	bufferevent_write(bev_, out.data(), out.length());

	this->state_ = READY;
	Log() << "Handshake successful (client ID: " << BinToHex(client_public_key_) << ")" << std::endl;
}

void CryptoPubServerConnection::OnError_(struct bufferevent* bev, const short what, void* this__) {
	auto this_ = (CryptoPubServerConnection*)this__;
	this_->OnError(what);
}

void CryptoPubServerConnection::OnError(const short what) {
	delete this;
}


CryptoPubClient::CryptoPubClient(struct sockaddr* addr, socklen_t addrlen, const std::string& secret_key, const std::string& server_public_key)
	: event_base_(event_base_new()),
	  bev_(bufferevent_socket_new(event_base_, -1, BEV_OPT_CLOSE_ON_FREE)),
    secret_key_(secret_key),
    server_public_key_(server_public_key),
	  state_(AWAITING_HANDSHAKE) {
	assert(secret_key_.length() == crypto_box_SECRETKEYBYTES);
	assert(server_public_key_.length() == crypto_box_PUBLICKEYBYTES);
	DerivePublicKey(secret_key_, &public_key_);

	bufferevent_setcb(bev_, &CryptoPubClient::OnReadable_, NULL, &CryptoPubClient::OnConnectOrError_, this);
	bufferevent_enable(bev_, EV_READ);
	bufferevent_enable(bev_, EV_WRITE);
	bufferevent_socket_connect(bev_, addr, addrlen);
}

CryptoPubClient::~CryptoPubClient() {
	bufferevent_free(bev_);
	event_base_free(event_base_);
}

CryptoPubClient* CryptoPubClient::FromHostname(const std::string& server_address, const std::string& server_port, const std::string& secret_key, const std::string& server_public_key) {
	struct addrinfo* res;
	int gai_ret = getaddrinfo(server_address.c_str(), server_port.c_str(), NULL, &res);
	if (gai_ret) {
		std::cerr << "Failed to resolve server_address: " << gai_strerror(gai_ret) << std::endl;
		return nullptr;
	}
	auto ret = new CryptoPubClient((struct sockaddr*)res->ai_addr, res->ai_addrlen, secret_key, server_public_key);
	freeaddrinfo(res);
	return ret;
}

void CryptoPubClient::OnReadable_(struct bufferevent* bev, void* this__) {
	auto this_ = (CryptoPubClient*)this__;
	this_->OnReadable();
}

void CryptoPubClient::OnReadable() {
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
		LogFatal() << "Protocol error (unexpected message type)" << std::endl;
		return;
	}

  std::unique_ptr<TLVNode> decrypted(DecryptDecode(ephemeral_secret_key_, server_ephemeral_public_key_, *decoded));
	if (!decrypted.get()) {
		LogFatal() << "Protocol error (decryption failure)" << std::endl;
		return;
	}

	switch (decrypted->GetType()) {
	}
}

void CryptoPubClient::OnHandshake(const TLVNode& decoded) {
	auto encrypted = decoded.FindChild(TLV_TYPE_ENCRYPTED);
	if (!encrypted) {
		LogFatal() << "Protocol error (server handshake -- no encrypted portion)" << std::endl;
		return;
	}

	std::unique_ptr<TLVNode> decrypted(DecryptDecode(secret_key_, server_public_key_, *encrypted));
	if (!decrypted.get()) {
		LogFatal() << "Protocol error (server handshake -- decryption failure)" << std::endl;
		return;
	}

	auto server_ephemeral_public_key = decrypted->FindChild(TLV_TYPE_PUBLIC_KEY);
	if (!server_ephemeral_public_key) {
		LogFatal() << "Protocol error (server handshake -- no ephemeral public key)" << std::endl;
		return;
	}
	server_ephemeral_public_key_ = server_ephemeral_public_key->GetValue();
	if (server_ephemeral_public_key_.length() != crypto_box_PUBLICKEYBYTES) {
		LogFatal() <<  "Protocol error (server handshake -- wrong ephemeral public key length)" << std::endl;
		return;
	}

	this->state_ = READY;
	Log() << "Handshake successful" << std::endl;
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

	std::string ephemeral_public_key;
	GenKeyPair(&ephemeral_secret_key_, &ephemeral_public_key);

	TLVNode handshake(TLV_TYPE_CLIENT_HANDSHAKE);
	handshake.AppendChild(new TLVNode(TLV_TYPE_PUBLIC_KEY, public_key_));
	TLVNode secure_handshake(TLV_TYPE_CLIENT_HANDSHAKE_SECURE);
	secure_handshake.AppendChild(new TLVNode(TLV_TYPE_PUBLIC_KEY, ephemeral_public_key));
	EncodeEncryptAppend(secret_key_, server_public_key_, secure_handshake, &handshake);

	std::string out;
	handshake.Encode(&out);
	bufferevent_write(bev_, out.data(), out.length());
}

void CryptoPubClient::OnError() {
	Log() << "Connection error" << std::endl;
}

void CryptoPubClient::Loop() {
	event_base_dispatch(event_base_);
}
