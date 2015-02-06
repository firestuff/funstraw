all: auth-client auth-server gen-key gen-keypair

%.o: %.cc
	g++ -std=c++11 -c -o $@ $<

auth-client: auth-client.o crypto.o tlv.o
	g++ -o auth-client auth-client.o crypto.o tlv.o -lsodium

auth-server: auth-server.o crypto.o tlv.o
	g++ -o auth-server auth-server.o crypto.o tlv.o -lsodium

gen-key: gen-key.o crypto.o tlv.o
	g++ -o gen-key gen-key.o crypto.o tlv.o -lsodium

gen-keypair: gen-keypair.o crypto.o tlv.o
	g++ -o gen-keypair gen-keypair.o crypto.o tlv.o -lsodium
