#include <iostream>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <cassert>

#include "openssl/err.h"
#include "cjson/cJSON.h"

#include "src/rsa_Crypto.h"
#include "src/abe_Crypto.h"
#include "src/SSL_socket.h"

#define CACERT "tmp/cacert.pem"
#define SERVER_CRT "tmp/servercert.pem"
#define SERVER_KEY "tmp/server.pem"
#define CHK_ERR(err, s) \
	if ((err) == -1)    \
	{                   \
		perror(s);      \
		exit(-2);       \
	}
#define SERVER_ADDR "127.0.0.1"
#define PORT 20001
#define SERVER_mode 1
using namespace std;

const char *RSA_private_key = "tmp/server.pem";

const char *RSA_public_key = "tmp/servercert.pem";

const char *RSA_ver_key = "tmp/clientcert.pem";

static string abe_pp, abe_msk;

static void *thread_keygenerate(void *arg)
{
	pthread_socket *ps_sock = (pthread_socket *)arg;
	string uuid, sign_type, user_sign, username, attibute, cipher;
	abe_user user;
	unsigned int sign_length;
	int ret = 0, request_code = 0;
	unsigned char RSA_sign_buf[257];
	SSL *ssl = NULL;
	SSL_CTX *ctx = InitSSL((char *)CACERT, (char *)SERVER_CRT, (char *)SERVER_KEY, SERVER_mode);
	if (ctx == NULL)
		goto exit;

	/*申请一个SSL套接字*/
	ssl = SSL_new(ctx);
	if (ssl <= 0)
	{
		SSL_CTX_free(ctx);
		printf("Error creating SSL new \n");
		goto exit;
	}
	/*绑定读写套接字*/
	SSL_set_fd(ssl, ps_sock->socket_d);
	SSL_accept(ssl);
	printf("链接已建立.开始 SSL 握手过程 \n");
	// 展示ssl信息
	show_SSL(ssl);

	/* 开始密钥生成,用SSL_write,SSL_read代替write,read */
	printf("Begin SSL data exchange\n");

	// begin json transportion
	SSL_Json_get(ssl, uuid, username, attibute, sign_type, user_sign, request_code);
	if (request_code != 0)
	{
		cout << "非用户注册，线程退出" << endl;
		SSL_response_error(ssl, uuid.c_str(), "非注册类型, 请确认后重试", 2);
		goto exit;
	}
	// 进行RSA签名的认证
	if (strcmp(sign_type.c_str(), "RSA") == 0)
	{ // 如果签名类型是RSA
		cout << "签名类型: RSA" << endl;
		ret = RSA_Verify(RSA_ver_key, username + attibute, (const unsigned char *)user_sign.c_str());
	}
	if (ret != 1)
	{
		cout << "验签失败，请传输正确的签名数据~~。" << endl;
		SSL_response_error(ssl, uuid, "验签失败，请传输正确的签名数据", 2);
		goto exit;
	}
	printf("验证签名of %s成功!\n", username.c_str());

	// 检索是否存在用户证书
	if (!check_cert("tmp/" + username + "cert.pem"))
	{ // 如果不存在
		cout << "用户证书不存在，请提醒用户及时申请证书" << endl;
		SSL_response_error(ssl, uuid, "用户证书不存在，请提醒用户及时申请证书", 1);
		goto exit;
	}

	// abe密钥生成,将密钥长度等信息发送给database
	user.user_id = username;
	user.user_attr = attibute;
	abe_KeyGen(user, abe_pp, abe_msk);
	if (1)
	{
		cipher = RSA_Encrypt(RSA_ver_key, user.user_key); // 如果加密类型为RSA加密
		// abe密钥签名
		RSA_Sign(RSA_private_key, cipher, RSA_sign_buf, sign_length);
	}
	cout << "密钥及签名生成完毕, 开始返回响应包" << endl;
	SSL_response_ok(ssl, uuid, "用户信息核验成功, 生成abe_密钥", cipher, RSA_sign_buf, sign_length, 0);
	/* 收尾工作 */
	SSL_shutdown(ssl);
	SSL_free(ssl);
	ssl = NULL;
	shutdown(ps_sock->socket_d, 2);

exit:
	if (ctx)
		SSL_CTX_free(ctx);
	if (ssl)
	{
		SSL_shutdown(ssl);
		SSL_free(ssl);
		shutdown(ps_sock->socket_d, 2);
	} /* send SSL/TLS close_notify */
	return NULL;
}

// listen a port, accepted register procedure in muti-thread, set max-connections such as 20.
int sock_init(int port = 20001)
{
	int listen_sock;
	int listen_max = 20;  // max listen number
	sockaddr_in sockaddr; // 定义IP地址结构
	int on = 1;
	listen_sock = socket(AF_INET, SOCK_STREAM, 0); // 初始化socket
	if (listen_sock == -1)
	{
		printf("socket create error \n");
		return -1;
	}
	if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1) // 设置ip地址可重用
	{
		printf("setsockopt error \n");
		return -1;
	}
	sockaddr.sin_port = htons(port);
	sockaddr.sin_family = AF_INET; // 设置结构类型为TCP/IP
	sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(listen_sock, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) == -1)
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
	pthread_t KenGen;
	if (!parameter_import_string(abe_pp, abe_msk))
	{
		cout << "参数导入失败，请重新尝试" << endl;
	}
	while (1)
	{
		pthread_socket ps;
		int accept_st;
		sockaddr_in accept_sockaddr; // 定义accept IP地址结构
		socklen_t addrlen = sizeof(accept_sockaddr);
		memset(&accept_sockaddr, 0, addrlen);
		accept_st = accept(listen_sock, (struct sockaddr *)&accept_sockaddr, &addrlen);
		if (accept_st == -1)
		{
			printf("accept error");
			continue;
		}
		ps.socket_d = accept_st;

		if (pthread_create(&KenGen, NULL, thread_keygenerate, &ps) != 0) // 创建接收信息线程
		{
			printf("create thread error to sock %d \n", accept_st);
		}
	}
	pthread_join(KenGen, NULL);
	// oabe::ShutdownOpenABE();
	return 0;
}

int main(void)
{
	sock_init();
}