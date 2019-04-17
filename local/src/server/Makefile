
OBJ=replay-server.o ../core/ArgParser.o ../core/HttpReplay.o

CXXFLAGS=-g -O2  -I/home/shinrich/openssl/include -I ../../include -I../../../include -std=c++17 


replay-server: ${OBJ}
	${CXX} -o replay-server ${OBJ}  -L../../../lib -L ../../../lib64 -L/opt/oath/openssl/1.1.1/lib -lssl -lcrypto -lpthread -lswoc++ -lyaml-cpp 
