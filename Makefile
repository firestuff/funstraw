all: auth-client auth-server gen-key gen-keypair

%.o: %.cc *.h Makefile
	g++ -I/usr/local/include -std=c++11 -g -c -o $@ $<

auth-client: auth-client.o crypto.o tlv.o
	g++ -L/usr/local/lib -o auth-client auth-client.o crypto.o tlv.o -lsodium -levent

auth-server: auth-server.o crypto.o tlv.o
	g++ -L/usr/local/lib -o auth-server auth-server.o crypto.o tlv.o -lsodium -levent

gen-key: gen-key.o crypto.o tlv.o
	g++ -L/usr/local/lib -o gen-key gen-key.o crypto.o tlv.o -lsodium -levent

gen-keypair: gen-keypair.o crypto.o tlv.o
	g++ -L/usr/local/lib -o gen-keypair gen-keypair.o crypto.o tlv.o -lsodium -levent
