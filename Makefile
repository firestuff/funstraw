all: server

server: server.cc
	g++ -o server server.cc nacl/build/instance1/lib/amd64/randombytes.o nacl/build/instance1/lib/amd64/libnacl.a
