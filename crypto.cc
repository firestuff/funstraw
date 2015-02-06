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


CryptoBase::CryptoBase(const int fd)
	: fd_(fd) {}

CryptoBase::~CryptoBase() {
	if (close(fd_)) {
		perror("close");
	}
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


CryptoPubServer::CryptoPubServer(const int fd, const std::string secret_key)
	: CryptoBase(fd),
	  secret_key_(secret_key),
    epoll_fd_(epoll_create(256)) {
	epoll_event event = {
		.events = EPOLLIN,
		.data = {
			.ptr = this,
		},
	};
	epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, fd, &event);
}

CryptoPubServer::~CryptoPubServer() {
	if (close(epoll_fd_)) {
		perror("close");
	}
}

void CryptoPubServer::OnReadable() {
	struct sockaddr_in6 client;
	socklen_t client_len = sizeof(client);
	auto client_fd = accept(fd_, (struct sockaddr*) &client, &client_len);
	if (client_fd == -1) {
		perror("accept");
		return;
	}

	char buf[128];
	inet_ntop(AF_INET6, &client.sin6_addr, buf, 128);
	std::cerr << "New connection from [" << buf << "]:" << ntohs(client.sin6_port) << std::endl;
	auto peer = new CryptoPubServerConnection(client_fd, secret_key_);
	
	epoll_event event = {
		.events = EPOLLIN,
		.data = {
			.ptr = peer,
		},
	};
	epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, client_fd, &event);
}

void CryptoPubServer::Loop() {
	while (1) {
		epoll_event events[10];
		auto num_events = epoll_wait(epoll_fd_, events, 10, -1);
		for (int i = 0; i < num_events; i++) {
			if (events[i].events & EPOLLIN) {
				auto obj = (CryptoBase*) events[i].data.ptr;
				obj->OnReadable();
			}
		}
	}
}


CryptoPubServerConnection::CryptoPubServerConnection(const int fd, const std::string secret_key)
	: CryptoBase(fd),
	  secret_key_(secret_key),
    state_(AWAITING_HANDSHAKE) {
}

void CryptoPubServerConnection::OnReadable() {
	char buf[128];
	if (read(fd_, buf, 128) == 0) {
		delete this;
		return;
	}
}
