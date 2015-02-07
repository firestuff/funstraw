#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <unistd.h>

#include <cassert>
#include <iostream>

#include <sodium/crypto_box.h>
#include <sodium/crypto_secretbox.h>
#include <sodium/randombytes.h>

#include "crypto.h"


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


CryptoPubServer::CryptoPubServer(const std::string& secret_key)
	: secret_key_(secret_key),
	  event_base_(event_base_new()) {
	struct sockaddr_in6 server_addr = {0};
	server_addr.sin6_family = AF_INET6;
	server_addr.sin6_addr = in6addr_any;
	server_addr.sin6_port = htons(4990);

	listener_ = evconnlistener_new_bind(event_base_, &CryptoPubServer::OnNewConn, this, LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_FREE, -1, (struct sockaddr*)&server_addr, sizeof(server_addr));
}

CryptoPubServer::~CryptoPubServer() {
	evconnlistener_free(listener_);
	event_base_free(event_base_);
}

void CryptoPubServer::OnNewConn(struct evconnlistener* listener, int client_fd, struct sockaddr* client_addr_, int client_addrlen, void* this__) {
	auto this_ = (CryptoPubServer*)this__;

	assert(client_addr_->sa_family == AF_INET6);
	auto client_addr = (struct sockaddr_in6*)client_addr_;

	char buf[128];
	inet_ntop(AF_INET6, &client_addr->sin6_addr, buf, 128);
	std::cerr << "New connection from [" << buf << "]:" << ntohs(client_addr->sin6_port) << std::endl;

	auto bev = bufferevent_socket_new(this_->event_base_, client_fd, BEV_OPT_CLOSE_ON_FREE);
	bufferevent_enable(bev, EV_READ);
	bufferevent_disable(bev, EV_WRITE);
	auto peer = new CryptoPubServerConnection(bev, this_->secret_key_);
	bufferevent_setcb(bev, &CryptoPubServerConnection::OnReadable, NULL, &CryptoPubServerConnection::OnError, peer);
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
	std::cerr << "Connection closed" << std::endl;
	bufferevent_free(bev_);
}

void CryptoPubServerConnection::OnReadable(struct bufferevent* bev, void* this__) {
	std::cerr << "OnReadable" << std::endl;
	auto this_ = (CryptoPubServerConnection*)this__;
	char buf[128];
	bufferevent_read(bev, buf, 128);
}

void CryptoPubServerConnection::OnError(struct bufferevent* bev, const short what, void* this__) {
	std::cerr << "OnError" << std::endl;
	auto this_ = (CryptoPubServerConnection*)this__;
	delete this_;
}


CryptoPubClient::CryptoPubClient(struct sockaddr* addr, socklen_t addrlen)
	: event_base_(event_base_new()),
	  bev_(bufferevent_socket_new(event_base_, -1, BEV_OPT_CLOSE_ON_FREE)) {
	bufferevent_socket_connect(bev_, addr, addrlen);
}

CryptoPubClient::~CryptoPubClient() {
	bufferevent_free(bev_);
	event_base_free(event_base_);
}

CryptoPubClient* CryptoPubClient::FromHostname(const std::string& server_address, const std::string& server_port) {
	struct addrinfo* res;
	int gai_ret = getaddrinfo(server_address.c_str(), server_port.c_str(), NULL, &res);
	if (gai_ret) {
		std::cerr << "Failed to resolve server_address: " << gai_strerror(gai_ret) << std::endl;
		return nullptr;
	}
	auto ret = new CryptoPubClient((struct sockaddr*)res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	return ret;
}

void CryptoPubClient::Loop() {
	event_base_dispatch(event_base_);
}
