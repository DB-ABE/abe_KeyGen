#include <iostream>
#include <string>
#include<unistd.h>

#include "openssl/ssl.h"
#include "openssl/err.h"

struct pthread_socket
{
	int socket_d;
};
//base64编码，用于传输加密和签名数据构造json包
char* base64Encode(const unsigned char *input, int length);
unsigned char* base64Decode(const char *input, int length, int *outputLength);

//用于SSL传输
void SSL_ReadAll(SSL *ssl, char *buf, size_t buf_len);
void SSL_WriteAll(SSL *ssl, char *buf, size_t buf_len);

//abe_KMS头文件
//用于初始化SSL
SSL_CTX* InitSSL(char *ca_path, char *client_crt_path,
 char *client_key_path, int mothflag);
//用于展示通讯对方的SSL证书
void show_SSL(SSL *ssl);

//用来检索对应用户的本地证书是否存在
bool check_cert(std::string cert_pwd);

//获取来自通讯方的请求数据
void SSL_Json_get(SSL *ssl, std::string &uuid, std::string &username, std::string &attibute,
                  std::string &sign_type, std::string &user_sign, int &code);

//发送数据给通讯方
void SSL_Json_write(SSL* ssl, char *json_str);

//返回给通讯方相应包
void SSL_response_error(SSL *ssl, std::string uuid, const char *msg, int error_code);
void SSL_response_ok(SSL *ssl, std::string uuid, const char *msg, const std::string cipher,
 unsigned char *RSA_sign_buf, unsigned int sign_length, int ok_code);

//释放SSL资源
void SSL_Shut(SSL *ssl, BIO *bio_req = NULL, char *dataStr = NULL);

//cert_KMS头文件
EVP_PKEY *SSL_PKEY_read(const char *key_path);

SSL_CTX *cert_SSL_init(const char *server_cert_path, const char *server_key_path);

X509 *cert_Gen(X509_REQ *req_new, EVP_PKEY *KMS_key);

void cert_save(X509 *cert);

X509 *cert_from_str(BIO *bio_req, char *dataStr, EVP_PKEY *KMS_key);

void SSL_cert_write(SSL *ssl, X509 *cert);