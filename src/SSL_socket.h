#include <iostream>
#include <string>
#include<unistd.h>

#include "openssl/ssl.h"
#include "openssl/err.h"

struct pthread_socket
{
	int socket_d;
};

char* base64Encode(const unsigned char *input, int length);

unsigned char* base64Decode(const char *input, int length, int *outputLength);

std::string subreplace(std::string resource_str, std::string sub_str, std::string new_str);

void SSL_ReadAll(SSL *ssl, char *buf, size_t buf_len);

void SSL_WriteAll(SSL *ssl, char *buf, size_t buf_len);

SSL_CTX* InitSSL(char *ca_path, char *client_crt_path, char *client_key_path, int mothflag);//与Keymanager重复

void show_SSL(SSL *ssl);

bool check_cert(std::string cert_pwd);

void SSL_Json_get(SSL *ssl, std::string &uuid, std::string &username, std::string &attibute,
                  std::string &sign_type, std::string &user_sign, int &code);

void SSL_Json_write(SSL* ssl, char *json_str);

void SSL_response_error(SSL *ssl, std::string uuid, const char *msg, int error_code);

void SSL_response_ok(SSL *ssl, std::string uuid, const char *msg, const std::string cipher, unsigned char *RSA_sign_buf, unsigned int sign_length, int ok_code);
