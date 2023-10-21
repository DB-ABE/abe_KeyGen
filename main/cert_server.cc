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
#include "Config.h"
#define PORT 20000
using namespace std;

static string cacert_path, server_key_path, server_cert_path;
static SSL_CTX *ctx = NULL; 
static EVP_PKEY *KMS_key = NULL;
static void* thread_certgenerate(void *arg){
    pthread_socket *ps_sock = (pthread_socket*) arg;
    cout<<"successfully connection! for socket:"<<ps_sock->socket_d<<endl;
	//变量区:
	int dataLen = 0; char crt_len[5] = {0}; char *dataStr = NULL;
	SSL* ssl = NULL; 
	BIO *bio_req = NULL;
	//代码区：
    ssl = SSL_new (ctx);
    if(ssl <= 0)
    {
        SSL_Shut(ssl);
		shutdown(ps_sock->socket_d, 2);
        printf("Error creating SSL new \n");
        return NULL;
    }
	/*绑定读写套接字*/
	SSL_set_fd (ssl, ps_sock->socket_d);
	SSL_accept (ssl);               
	printf("链接已建立.开始 SSL 传输 \n");
	//由客户端认证servercert.pem
	//...
	cout<<"由客户端进行证书认证"<<endl;

	//接收来自客户端的证书请求
	SSL_ReadAll(ssl, crt_len, sizeof(crt_len) - 1);
	dataLen = stoi((const char*)crt_len, 0, 16);
	dataStr = (char *)malloc(1 + sizeof(char) * dataLen);
	SSL_ReadAll(ssl, dataStr, dataLen + 1);
	
	// 创建证书
    X509 *cert = cert_from_str(bio_req, dataStr, KMS_key);
	SSL_cert_Write(ssl, cert);

	X509_free(cert);
	SSL_Shut(ssl, bio_req, dataStr);
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
	cout<<"导入配置文件"<<endl;
	json config = loadConfiguration("./conf/Config.json");
	server_key_path = getConfigString(config, "KMS_private_key");
	server_cert_path = getConfigString(config, "KMS_cert");
	ctx = cert_SSL_Init(server_cert_path.c_str(), server_key_path.c_str());
	/*申请一个SSL套接字*/
	if (ctx == NULL)
	{
		cout<<"证书导入失败"<<endl;
		return -1;
	}
	// 加载 server 的私钥
    KMS_key = SSL_PKEY_Read(server_key_path.c_str());
	if(KMS_key) {
		sock_init(PORT);
		EVP_PKEY_free(KMS_key);
	}
	SSL_CTX_free(ctx);
	return 0;
	//ShutdownOpenABE();//没有用上
}
//g++ -o cert_server -std=c++11 -pthread -Wall -g -O2 -DSSL_LIB_INIT  -I/usr/local/include -L/usr/local/lib cert_server.cc SSL_socket.cc -lcrypto -lssl -lcjson -ldl