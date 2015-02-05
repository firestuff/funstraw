all: auth-server gen-pubkeypair

auth-server: auth-server.cc
	g++ -o auth-server auth-server.cc nacl/build/instance1/lib/amd64/randombytes.o nacl/build/instance1/lib/amd64/libnacl.a

gen-pubkeypair: gen-pubkeypair.cc
	g++ -o gen-pubkeypair gen-pubkeypair.cc nacl/build/instance1/lib/amd64/randombytes.o nacl/build/instance1/lib/amd64/libnacl.a
