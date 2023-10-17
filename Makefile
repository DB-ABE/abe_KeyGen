.PHONY: all

CXX := g++
CXX11FLAGS := -std=c++11
OS_CXXFLAGS := 
CXXFLAGS := $(CXX11FLAGS)$(OS_CXXFLAGS) -pthread -Wall -g -O2 -DSSL_LIB_INIT  -I/usr/local/include -fsanitize=address
LDFLAGS :=  -L/usr/local/lib
LIBS := -lcrypto -lrelic -lrelic_ec -lopenabe -lssl -lmysqlclient -lcjson -ldl
SRCFLAGS := ./src/
all: practice

practice:
	$(CXX) -o cl $(CXXFLAGS) $(LDFLAGS) Database.cc $(SRCFLAGS)rsa_Crypto.cc $(SRCFLAGS)abe_Crypto.cc $(SRCFLAGS)SSL_socket.cc $(LIBS)
	$(CXX) -o sl $(CXXFLAGS) $(LDFLAGS) Keymanager.cc $(SRCFLAGS)rsa_Crypto.cc $(SRCFLAGS)abe_Crypto.cc $(SRCFLAGS)SSL_socket.cc $(LIBS)
	$(CXX) -o cert_req $(CXXFLAGS) $(LDFLAGS) cert_client.cc $(SRCFLAGS)SSL_socket.cc $(LIBS)
	$(CXX) -o cert_gen $(CXXFLAGS) $(LDFLAGS) cert_server.cc $(SRCFLAGS)SSL_socket.cc $(LIBS)
clean:
	rm -rf *.o practice setup encrypt decrypt files/*
#g++ -o cl -std=c++11 -pthread -Wall -g -O2 -DSSL_LIB_INIT  -I/usr/local/include -L/usr/local/lib Database.cc rsa_Crypto.cc abe_Crypto.cc -lcrypto -lrelic -lrelic_ec -lopenabe -lssl -lmysqlclient -ldl
#g++ -o sl -std=c++11 -pthread -Wall -g -O2 -DSSL_LIB_INIT  -I/usr/local/include -L/usr/local/lib Keymanager.cc rsa_Crypto.cc abe_Crypto.cc -lcrypto -lrelic -lrelic_ec -lopenabe -lssl -lmysqlclient -ldl
