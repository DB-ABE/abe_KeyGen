#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>

#include "SSL_socket.h"
#define SERVER_ADDR "127.0.0.1"
#define PORT 20000
using namespace std;

const char * cacert_path = "../tmp/cacert.pem";
const char * server_key_path = "../tmp/server.pem";
const char * server_cert_path = "../tmp/servercert.pem";
struct pthread_socket
{
	int socket_d;
};
static void* thread_certgenerate(void *arg){
    pthread_socket *ps_sock = (pthread_socket*) arg;
    cout<<"successfully connection! for socket:"<<ps_sock->socket_d<<endl;
	//变量区:
	int dataLen = 0; char crt_len[5] = {0}; char *dataStr = NULL;
	SSL* ssl = NULL; SSL_CTX* ctx = NULL; 
	X509_REQ *req_new = NULL; EVP_PKEY *caKey = NULL; X509 *cert = NULL;
	char *DataString_new = NULL; BIO *bio_req = NULL;
	//代码区：
	
	{
		SSL_METHOD *meth;
		/* * 算法初始化 * */   
		SSL_library_init();
		// 加载SSL错误信息
		SSL_load_error_strings();
	
		// 添加SSL的加密/HASH算法
		SSLeay_add_ssl_algorithms();
		meth = (SSL_METHOD *)TLS_server_method();
		/* 创建SSL会话环境 */
		ctx = SSL_CTX_new (meth);                    
		if(ctx == NULL)
		{
			printf ("SSL_CTX_new error\n");
			return NULL;
		}
		// /*验证与否,是否要验证对方*/
		SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE,NULL);   

		/*加载自己的证书*/
		if (SSL_CTX_use_certificate_file(ctx, server_cert_path, SSL_FILETYPE_PEM) <= 0) 
		{
			printf("SSL_CTX_use_certificate_file error\n");
			return NULL;
		}
		/*加载自己的私钥,以用于签名*/
		if (SSL_CTX_use_PrivateKey_file(ctx, server_key_path, SSL_FILETYPE_PEM) <= 0) 
		{
			printf("SSL_CTX_use_PrivateKey_file error\n");
			return NULL;
		}
		// 设置证书私钥文件的密码
		//SSL_CTX_set_default_passwd_cb_userdata(ctx, pw);

		/*调用了以上两个函数后,检验一下自己的证书与私钥是否配对*/
		if (!SSL_CTX_check_private_key(ctx)) 
		{
			printf("SSL_CTX_check_private_key error\n");
			return NULL;
		} 
	}

	{
		/*申请一个SSL套接字*/
		ssl = SSL_new (ctx);
		if(ssl <= 0)
		{
			printf("Error creating SSL new \n");
			goto exit;
		}
		/*绑定读写套接字*/
		SSL_set_fd (ssl, ps_sock->socket_d);
		SSL_accept (ssl);               
		printf("链接已建立.开始 SSL 传输 \n");
		//由客户端认证servercert.pem
		//...
		cout<<"由客户端进行证书认证"<<endl;

		SSL_ReadAll(ssl, crt_len, sizeof(crt_len));
		dataLen = stoi((const char*)crt_len, 0, 16);
		dataStr = (char *)malloc(1 + sizeof(char) * dataLen);
		SSL_ReadAll(ssl, dataStr, dataLen + 1);
	}

	{
		bio_req = BIO_new(BIO_s_mem());
		BIO_puts(bio_req, dataStr);
		req_new = PEM_read_bio_X509_REQ(bio_req, NULL, NULL, NULL);
		if (req_new == NULL) {
			fprintf(stderr, "无法解析证书请求\n");
			goto exit;
			// 处理错误
		}
	}
	// 加载 server 的私钥
    {
		FILE *caKeyFile = fopen(server_key_path, "rb");
		if (!caKeyFile) {
			fprintf(stderr, "无法打开 KMS 的私钥文件\n");
			goto exit;
		}
		caKey = PEM_read_PrivateKey(caKeyFile, NULL, NULL, NULL);
		fclose(caKeyFile);
		if (!caKey) {
			fprintf(stderr, "无法读取 KMS 的私钥\n");
			goto exit;
		}
	}
	// 创建证书
    cert = X509_new();
    if (!cert) {
        fprintf(stderr, "无法创建证书对象\n");
        goto exit;
    }

	{
		// 设置证书版本号
		X509_set_version(cert, 2); // 版本号为2代表X.509 v3

		// 设置证书序列号
		ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);

		// 设置证书有效期
		X509_gmtime_adj(X509_get_notBefore(cert), 0);
		X509_gmtime_adj(X509_get_notAfter(cert), 31536000L); // 有效期为1年
		
		// 设置证书主题
		X509_set_subject_name(cert, X509_REQ_get_subject_name(req_new));

		// 设置证书颁发者
		X509_set_issuer_name(cert, X509_REQ_get_subject_name(req_new));
		
		// 设置证书公钥
		EVP_PKEY *pkey_req = X509_REQ_get_pubkey(req_new);
		X509_set_pubkey(cert, pkey_req);
		EVP_PKEY_free(pkey_req);
		pkey_req = NULL;
	}
	// 签名证书
    if (!X509_sign(cert, caKey, EVP_sha512())) {
        fprintf(stderr, "无法签名证书\n");
        goto exit;
    }
    X509_REQ_free(req_new);
	req_new = NULL;
    EVP_PKEY_free(caKey);
	caKey = NULL;
	{
		X509_NAME_ENTRY* entry = NULL;
		ASN1_STRING* cnData = NULL;
		char* cnStr = NULL;
		char *suffix = NULL;
		FILE *certFile = NULL;
		//获取证书主题
		X509_NAME* subject = X509_get_subject_name(cert);
		// 查找 Common Name (CN) 字段
		int cnIndex = X509_NAME_get_index_by_NID(subject, NID_commonName, -1);
		if (cnIndex < 0) {
			X509_NAME_free(subject);
			// 处理未找到 CN 字段的情况
			printf("未在证书中找到 CN 字段\n");
			goto exit;
		}
	
		// 获取 CN 字段的值
		entry = X509_NAME_get_entry(subject, cnIndex);
		cnData = X509_NAME_ENTRY_get_data(entry);

		if (cnData == NULL) {
			X509_NAME_ENTRY_free(entry);
			// 处理获取 CN 值失败的情况
			printf("获取证书中 CN 字段失败\n");
			goto exit;
		}
		// 将 CN 字段的值转换为 C 字符串
		cnStr = (char*)ASN1_STRING_get0_data(cnData);
		if (cnStr == NULL) {
			ASN1_STRING_free(cnData);
			// 处理转换失败的情况
			printf("获取证书中 CN 字段转换字符串失败\n");
			goto exit;
		}
		suffix = (char *)malloc(5 + strlen(cnStr) * sizeof(char));
		sprintf(suffix, "%s.pem", cnStr);
		// 将证书保存到文件
		certFile = fopen(suffix, "wb");
		free(suffix);
		suffix = NULL;
		cnStr = NULL;

		if (!certFile) {
			fprintf(stderr, "无法打开证书文件\n");
			goto exit;
		}

		if (PEM_write_X509(certFile, cert) != 1) {
			// 处理写入失败的情况
			fclose(certFile);
			goto exit;
		}
		fclose(certFile);
	}

	{
		// 将证书转换为字符串
		BIO* bio_cert = BIO_new(BIO_s_mem());
		if (bio_cert == NULL) {
			perror("BIO 对象创建失败");
			goto exit;
		}

		if (!PEM_write_bio_X509(bio_cert, cert)) {
			perror("证书转换为字符串失败");
			BIO_free(bio_cert);
			bio_cert = NULL;
			goto exit;
		}
		X509_free(cert);
		cert = NULL;
		char* certStr;
		long certSize = BIO_get_mem_data(bio_cert, &certStr);
		if (certSize <= 0) {
			perror("无效的证书字符串");
			goto exit;
		}
		char *DataString_new = (char *)malloc(1 + sizeof(char) * certSize);
		sprintf(DataString_new, "%.*s", int(certSize), certStr);
		printf("证书字符串：\n%s\n", DataString_new);
		sprintf((char *)crt_len, "%02x", int(certSize));
        SSL_WriteAll(ssl, crt_len, sizeof(crt_len));
        SSL_WriteAll(ssl, DataString_new, certSize + 1);
		BIO_free(bio_cert);
		bio_cert = NULL;
	}
	// 打印证书字符串
	
	free(DataString_new);
	DataString_new = NULL;

exit:
	if(dataStr) free(dataStr);
	if(caKey) EVP_PKEY_free(caKey);
	if(bio_req) BIO_free(bio_req);
	SSL_shutdown (ssl);
	SSL_free (ssl);
	shutdown (ps_sock->socket_d,2);
	return 0;
}

int sock_init(int port = 20000){
    int listen_sock;
	int listen_max = 20;//max listen number
	sockaddr_in sockaddr; //定义IP地址结构
	int on = 1;
	listen_sock = socket(AF_INET, SOCK_STREAM, 0); //初始化socket
	if (listen_sock == -1)
	{
		printf("socket create error \n");
		return -1;
	}
	if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1) //设置ip地址可重用
	{
		printf("setsockopt error \n");
		return -1;
	}
	sockaddr.sin_port = htons(port);
	sockaddr.sin_family = AF_INET;    //设置结构类型为TCP/IP
	sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);//绑定ip
	if (bind(listen_sock, (struct sockaddr *) &sockaddr, sizeof(sockaddr)) == -1)
	{
		printf("bind error \n");
		return -1;
	}

	if (listen(listen_sock, listen_max) == -1) //     服务端开始监听
	{
		printf("listen error \n");
		return -1;
	}
	printf("init successful!, listen begin \n");
	pthread_t Cert_Gen;
	while (1)
    	{
			pthread_socket ps;
			int accept_st;
    		sockaddr_in accept_sockaddr; //定义accept IP地址结构
    		socklen_t addrlen = sizeof(accept_sockaddr);
    		memset(&accept_sockaddr, 0, addrlen);
			accept_st = accept(listen_sock, (struct sockaddr*) &accept_sockaddr,&addrlen);
			if (accept_st == -1)
    		{
        		printf("accept error");
        		continue;
    		}
			ps.socket_d = accept_st;
			if (pthread_create(&Cert_Gen, NULL, thread_certgenerate, &ps) != 0)//创建接收信息线程
        	{
            		printf("create thread error to sock %d \n", accept_st);
        	}
		}
	return 0;
}

int main(void){
	sock_init(PORT);
	//ShutdownOpenABE();//没有用上
}
//g++ -o cert_server -std=c++11 -pthread -Wall -g -O2 -DSSL_LIB_INIT  -I/usr/local/include -L/usr/local/lib cert_server.cc SSL_socket.cc -lcrypto -lssl -lcjson -ldl