all: auth-server gen-key gen-keypair

%.o: %.cc
	g++ -std=c++11 -c -o $@ $<

auth-server: auth-server.o crypto.o
	g++ -o auth-server auth-server.o crypto.o nacl/build/instance1/lib/amd64/randombytes.o nacl/build/instance1/lib/amd64/libnacl.a

gen-key: gen-key.o crypto.o
	g++ -o gen-key gen-key.o crypto.o nacl/build/instance1/lib/amd64/randombytes.o nacl/build/instance1/lib/amd64/libnacl.a

gen-keypair: gen-keypair.o crypto.o
	g++ -o gen-keypair gen-keypair.o crypto.o nacl/build/instance1/lib/amd64/randombytes.o nacl/build/instance1/lib/amd64/libnacl.a
