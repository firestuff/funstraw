all: auth-server gen-keypair

%.o: %.cc
	g++ -c -o $@ $<

auth-server: auth-server.o crypto.o
	g++ -o auth-server auth-server.o crypto.o nacl/build/instance1/lib/amd64/randombytes.o nacl/build/instance1/lib/amd64/libnacl.a

gen-keypair: gen-keypair.o crypto.o
	g++ -o gen-keypair gen-keypair.o crypto.o nacl/build/instance1/lib/amd64/randombytes.o nacl/build/instance1/lib/amd64/libnacl.a
