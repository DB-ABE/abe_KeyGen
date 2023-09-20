.PHONY: all

CXX := g++
CXX11FLAGS := -std=c++11
OS_CXXFLAGS := 
CXXFLAGS := $(CXX11FLAGS)$(OS_CXXFLAGS) -pthread -Wall -g -O2 -DSSL_LIB_INIT  -I/usr/local/include
LDFLAGS :=  -L/usr/local/lib64
LIBS := -lcrypto -lrelic -lrelic_ec -lopenabe -lssl -ldl
 #LIBS += $$PWD/lib/libssl.a
 #LIBS += $$PWD/lib/libcrypto.a
 #LIBS += -ldl

all: practice

practice:
	$(CXX) -o abe_test $(CXXFLAGS) $(LDFLAGS) abe_test.cc $(LIBS)
#	$(CXX) -o sm2_test $(CXXFLAGS) $(LDFLAGS) sm2_test.cc $(LIBS)
#	$(CXX) -o sm2_Crypto $(CXXFLAGS) $(LDFLAGS) sm2_Crypto.cc $(LIBS)
#	$(CXX) -o abe_Crypto $(CXXFLAGS) $(LDFLAGS) abe_Crypto.cc $(LIBS)
	$(CXX) -o Crypto $(CXXFLAGS) $(LDFLAGS) Crypto.cc abe_Crypto.cc rsa_Crypto.cc $(LIBS)
#	$(CXX) -o openssl $(CXXFLAGS) $(LDFLAGS) openssl.cc $(LIBS)
clean:
	rm -rf *.o practice setup encrypt decrypt files/*

#g++ ssl_client.cc abe_Crypto.cc -I/usr/local/include -L/usr/local/lib64 -lcrypto -lssl -ldl -lrelic -lrelic_ec -lopenabe -o cl
#g++ -o Crypto -std=c++11 -pthread -Wall -g -O2 -DSSL_LIB_INIT  -I/usr/local/include -L/usr/local/lib64 Crypto.cc abe_Crypto.cc rsa_Crypto.cc -lcrypto -lrelic -lrelic_ec -lopenabe -lssl -ldl