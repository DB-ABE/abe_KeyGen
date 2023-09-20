#include<iostream>
#include<sys/socket.h>
#include<stdlib.h>
#include<string.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<pthread.h>
#include<fstream>
#include<unistd.h>
#include<cassert>

#include "openssl/crypto.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/rsa.h"      
#include "openssl/crypto.h"

#include "rsa_Crypto.h"
#include "abe_Crypto.h"

#define CACERT "../tmp/ca.cert"
#define SERVER_CRT "../tmp/server.cert"
#define SERVER_KEY "../tmp/server.pem"
#define CHK_ERR(err,s) if ((err) == -1) { perror(s); exit(-2); }
#define SERVER_ADDR "127.0.0.1"
#define PORT 20001
#define SERVER_mode 1
#define CLIENT_mode 0

const char *RSA_private_key = "./prikey.pem";

const char *RSA_public_key = "./pubkey.pem";

using namespace std;

struct pthread_socket
{
	int socket_d;
};

bool abe_flag = true;

void abe_lock(){
  while(abe_flag == false){
    sleep(0.05);
  }
  abe_flag = false;
}

void abe_unlock(){
	sleep(2);
  abe_flag = true;
}

SSL_CTX* InitSSL(char *ca_path, char *client_crt_path, char *client_key_path, int mothflag)
{
    SSL_CTX* ctx = NULL;
    SSL_METHOD *meth;
 
    /* * 算法初始化 * */   
    SSL_library_init();
    // 加载SSL错误信息
    SSL_load_error_strings();
 
    // 添加SSL的加密/HASH算法
    SSLeay_add_ssl_algorithms();
    
    /*采用什么协议(SSLv2/SSLv3/TLSv1)在此指定*/
    if(mothflag)
        meth = (SSL_METHOD *)TLS_server_method();
    else
        meth = (SSL_METHOD *)TLS_client_method();
    /* 创建SSL会话环境 */
    ctx = SSL_CTX_new (meth);                    
    if(ctx == NULL)
    {
        printf ("SSL_CTX_new error\n");
        return NULL;
    }
  
    // /*验证与否,是否要验证对方*/
   SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);   
    // /*若验证对方,则放置CA证书*/
   SSL_CTX_load_verify_locations(ctx,ca_path,NULL); 

    /*加载自己的证书*/
    if (SSL_CTX_use_certificate_file(ctx, client_crt_path, SSL_FILETYPE_PEM) <= 0) 
    {
        printf("SSL_CTX_use_certificate_file error\n");
        goto exit;
    }
    /*加载自己的私钥,以用于签名*/
    if (SSL_CTX_use_PrivateKey_file(ctx, client_key_path, SSL_FILETYPE_PEM) <= 0) 
    {
        printf("SSL_CTX_use_PrivateKey_file error\n");
        goto exit;
    }

    // 设置证书私钥文件的密码
    //SSL_CTX_set_default_passwd_cb_userdata(ctx, pw);

    /*调用了以上两个函数后,检验一下自己的证书与私钥是否配对*/
    if (!SSL_CTX_check_private_key(ctx)) 
    {
        printf("SSL_CTX_check_private_key error\n");
        goto exit;
    } 
    return ctx;

exit:
    if(ctx) SSL_CTX_free (ctx);
    return NULL;
}

static void* thread_keygenerate(void *arg)
{
	pthread_socket *ps_sock = (pthread_socket*) arg;
	string username, attibute, abe_ct,cipher;
	abe_user user;
	unsigned int sign_length;
	int ret = 0;
	char *str = NULL;
	char buf[1025] = {0};
	const int buf_len=sizeof(buf);
	X509* server_cert = NULL;
	SSL* ssl = NULL;
    SSL_CTX* ctx = InitSSL((char *)CACERT, (char *)SERVER_CRT, (char *)SERVER_KEY, SERVER_mode);
    if(ctx == NULL) goto exit;
	
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
    printf("链接已建立.开始 SSL 握手过程 \n");

	/*打印所有加密算法的信息(可选)*/
    printf ("SSL connection using %s\n", SSL_get_cipher (ssl));

    /*得到服务端的证书并打印些信息(可选) */
    server_cert = SSL_get_peer_certificate (ssl);      
    printf ("Database server certificate:\n");
	str = X509_NAME_oneline (X509_get_subject_name (server_cert),0,0);
    printf ("/t subject: %s\n", str);
    free (str);
	str = X509_NAME_oneline (X509_get_issuer_name  (server_cert),0,0);
    printf ("/t issuer: %s\n", str);
    free (str);
	X509_free (server_cert);  /*如不再需要,需将证书释放 */

	/* 开始密钥生成,用SSL_write,SSL_read代替write,read */
    printf("Begin SSL data exchange\n");
	
	//接收用户id
	memset (buf,0,1024);
	SSL_read (ssl, buf, 1024); 
	username.assign(buf);
	printf ("Got user id:'%s'\n", buf);

	//接收用户属性
	memset (buf,0,1024);
	SSL_read (ssl, buf, 1024); 
	attibute.assign(buf);
	printf ("Got user attibute:'%s'\n", buf);

	//接收数据库对该用户的签名
	memset (buf,0,1025);
	SSL_read (ssl, buf, 1025); 
	printf ("Got signature: of %s\n", username.c_str());

	//对签名进行验证
	ret = RSA_Verify(RSA_public_key, username+attibute, buf);
	if(ret != 1){
		cout<<"验签失败，请数据库传输正确的签名数据~~。"<<endl;
		goto exit;
	}
	printf("验证签名of %s成功!\n", username.c_str());

	//abe密钥生成,将密钥长度等信息发送给database
	user.user_id = username;
	user.user_attr = attibute;
	abe_lock();
	abe_KeyGen(user);
	//KeyGen_abe(user);
	memset(buf,0,1025);
	cipher = RSA_Encrypt(RSA_public_key, user.user_key);
	printf ("Got abe_key:\n");
	for(int i = 0; i < int(cipher.length()); i++)buf[i] = cipher[i];
	buf[buf_len-1] = cipher.length()/RSA_Decrypt_length;
	//abe_ct = RSA_Decrypt(RSA_private_key, cipher);
    SSL_write (ssl, buf, 1025);//发送abe密钥
	cout<<"成功发送abe密钥for user:"<<username<<endl;

	//abe与rsa加解密测试，可删
	user.user_key = RSA_Decrypt(RSA_private_key, cipher);
	abe_Encrypt("test", "attr1 and attr2", abe_ct);
    abe_Decrypt(abe_ct, user, abe_ct);
	

	//abe密钥签名
	memset(buf,0,1025);
	RSA_Sign(RSA_private_key, cipher.c_str(), buf, sign_length);
	cout<<"发送abe签名数据:";
	buf[buf_len-1] = sign_length/RSA_Decrypt_length;
	SSL_write (ssl, buf, 1025);

	
    /* 收尾工作 */
	SSL_shutdown (ssl);
    shutdown (ps_sock->socket_d,2);
	abe_unlock();
	
exit:
	//if(ps_sock)free(ps_sock);
	if(ctx) SSL_CTX_free(ctx);
    if(ssl) SSL_free (ssl);
	return &abe_flag;
}



//listen a port, accepted register procedure in muti-thread, set max-connections such as 20.
int sock_init(int port = 20001){
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
	sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
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
	pthread_t KenGen;
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
			if (pthread_create(&KenGen, NULL, thread_keygenerate, &ps) != 0)//创建接收信息线程
        	{
            		printf("create thread error to sock %d \n", accept_st);
        	}
		}
	return 0;
}
int test_abe(){
    string abe_pt1="Hello world!", abe_pt2, ct, policy="attr1 and attr2";
    abe_user zhangsan;
    zhangsan.user_id="zhangsan";
    zhangsan.user_attr="|attr1|attr2";
    abe_init();
    abe_KeyGen(zhangsan);
    abe_Encrypt(abe_pt1, policy, ct);
    abe_Decrypt(ct, zhangsan, abe_pt2);
    return 1;
}
int main(void){
	if(abe_init()) sock_init();
	//ShutdownOpenABE();//没有用上
}