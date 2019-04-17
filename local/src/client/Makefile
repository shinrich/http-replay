
OBJ=replay-client.o ../core/ArgParser.o ../core/HttpReplay.o

CXXFLAGS=-g -I/home/shinrich/openssl/include -I ../../include -I../../../include -std=c++17


replay-client: ${OBJ}
	${CXX} -o replay-client ${OBJ} -L../../../lib -L ../../../lib64 -L/opt/oath/openssl/1.1.1/lib -lssl -lcrypto -lpthread -lswoc++ -lyaml-cpp
