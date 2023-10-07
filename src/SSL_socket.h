#include <iostream>
#include <string>

#include "openssl/ssl.h"
#include "openssl/err.h"
using namespace std;

char* base64Encode(const unsigned char* input, int length);

unsigned char* base64Decode(const char* input, int length, int* outputLength);

string subreplace(string resource_str, string sub_str, string new_str);

void SSL_ReadAll(SSL *ssl, char *buf, size_t buf_len);

void SSL_WriteAll(SSL *ssl, char *buf, size_t buf_len);

SSL_CTX* InitSSL(char *ca_path, char *client_crt_path, char *client_key_path,int mothflag);//与Keymanager重复