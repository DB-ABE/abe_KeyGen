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
#include "openssl/err.h"
#include "openssl/rsa.h"      
#include "openssl/crypto.h"
#include "cjson/cJSON.h"

#include "rsa_Crypto.h"
#include "abe_Crypto.h"
#include "SSL_socket.h"

#define CACERT "../tmp/cacert.pem"
#define SERVER_CRT "../tmp/servercert.pem"
#define SERVER_KEY "../tmp/server.pem"
#define CHK_ERR(err,s) if ((err) == -1) { perror(s); exit(-2); }
#define SERVER_ADDR "127.0.0.1"
#define PORT 20001
#define SERVER_mode 1
#define CLIENT_mode 0

const char *RSA_private_key = "../tmp/client.pem";

const char *RSA_public_key = "../tmp/clientcert.pem";

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
  abe_flag = true;
}

bool check_cert(string cert_pwd){
	if(access(cert_pwd.c_str(), F_OK) == 0){
		cout<<"用户的证书存在, 可以继续~~"<<endl;
		return true;
	}
	cout<<"该用户不存在证书"<<endl;
	return false;
}

static void* thread_keygenerate(void *arg)
{
	char tmpt[5];//用来进行16进制->char类型的转换
	unsigned char json_len_hex[16]="0";
	int json_len;
	cJSON *request = cJSON_CreateObject();
	cJSON *response = cJSON_CreateObject();
	char *json_str = NULL;
	cJSON *key = NULL;

	pthread_socket *ps_sock = (pthread_socket*) arg;
	string uuid, username, attibute, cipher;
	abe_user user;
	unsigned int sign_length;
	int ret = 0;
	char *str = NULL;
	char buf[1024]={0};
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


	//begin json transportion
	SSL_ReadAll (ssl, (char*)json_len_hex, sizeof(json_len_hex)); 
	json_len = stoi((const char*)json_len_hex, 0, 16);
	cout<<"接收到请求包长度:"<<json_len<<endl;
	json_str = (char *)malloc(sizeof(char) * json_len);
	SSL_ReadAll (ssl, json_str, json_len);
	request = cJSON_Parse(json_str);
	free(json_str);
	key = cJSON_GetObjectItem(request, "type");//提取注册类型
	if(key->valueint != 0){
		cout<<"非用户注册，线程退出"<<endl;
		cJSON_AddNumberToObject(response, "code", 2);
		cJSON_AddStringToObject(response, "msg", "非注册类型，线程退出~~");
		cJSON *data = cJSON_CreateObject();
		cJSON_AddStringToObject(data, "uuid", uuid.c_str());
		cJSON_AddItemToObject(response, "data", data);
		json_str = cJSON_Print(response);
        cout<<"响应包长度:"<<strlen(json_str)<<endl;
        sprintf((char *)json_len_hex, "%x", int(strlen(json_str)));
        SSL_WriteAll (ssl, (char*)json_len_hex, sizeof(json_len_hex));
        SSL_WriteAll (ssl, json_str, strlen(json_str));
		free(json_str);
		data = NULL;
		goto exit;
	}
	key = cJSON_GetObjectItem(request, "uuid");//提取uuid
	uuid.assign(key->valuestring);
	cout<<"uuid: "<<key->valuestring<<endl;
	key = cJSON_GetObjectItem(request, "username");//提取user_id
	username.assign(key->valuestring);
	cout<<"username_json: "<<key->valuestring<<endl;
	key = cJSON_GetObjectItem(request, "attribute");//提取uer_attribute
	attibute.assign(key->valuestring);
	cout<<"attribute_json: "<<key->valuestring<<endl;
	key = cJSON_GetObjectItem(request, "dbSignature");
	printf ("Got signature: of %s\n", username.c_str());//提取并转换签名信息
	for(int i = 0; i < int(strlen(key->valuestring)/2); i++){
		sprintf(tmpt, "0x%c%c", key->valuestring[i*2], key->valuestring[i*2+1]);
		cipher += char(stoi(tmpt, 0, 16));
	}
	key = cJSON_GetObjectItem(request, "dbSignatureType");//提取签名类型

	//进行RSA签名的认证
	if(strcmp(key->valuestring, "RSA") == 0){//如果签名类型是RSA
		cout<<"签名类型: RSA"<<endl;
		ret = RSA_Verify(RSA_public_key, username+attibute, cipher.c_str());
	}

	if(ret != 1){
		cout<<"验签失败，请数据库传输正确的签名数据~~。"<<endl;
		cJSON_AddNumberToObject(response, "code", 2);
		cJSON_AddStringToObject(response, "msg", "验签失败，请数据库传输正确的签名数据");
		cJSON *data = cJSON_CreateObject();
		cJSON_AddStringToObject(data, "uuid", uuid.c_str());
		cJSON_AddItemToObject(response, "data", data);
		json_str = cJSON_Print(response);
        cout<<"响应包长度:"<<strlen(json_str)<<endl;
        sprintf((char *)json_len_hex, "%x", int(strlen(json_str)));
        SSL_WriteAll (ssl, (char*)json_len_hex, sizeof(json_len_hex));
        SSL_WriteAll (ssl, json_str, strlen(json_str));
		free(json_str);
		data = NULL;
		goto exit;
	}
	printf("验证签名of %s成功!\n", username.c_str());

	//检索是否存在用户证书
	if(!check_cert("../tmp/client.pem")){//如果不存在
		cout<<"用户证书不存在，请提醒用户及时申请证书"<<endl;
		cJSON_AddNumberToObject(response, "code", 1);
		cJSON_AddStringToObject(response, "msg", "用户证书不存在，请提醒用户及时申请证书");
		cJSON *data = cJSON_CreateObject();
		cJSON_AddStringToObject(data, "uuid", uuid.c_str());
		cJSON_AddItemToObject(response, "data", data);
		json_str = cJSON_Print(response);
        cout<<"响应包长度:"<<strlen(json_str)<<endl;
        sprintf((char *)json_len_hex, "%x", int(strlen(json_str)));
        SSL_WriteAll (ssl, (char*)json_len_hex, sizeof(json_len_hex));
        SSL_WriteAll (ssl, json_str, strlen(json_str));
		free(json_str);
		data = NULL;
		goto exit;
	}

	//abe密钥生成,将密钥长度等信息发送给database
	cJSON_AddNumberToObject(response, "code", 0);
	cJSON_AddStringToObject(response, "msg", "用户信息核验成功, 生成abe_密钥");
	user.user_id = username;
	user.user_attr = attibute;
	abe_lock();
	abe_KeyGen(user);
	//KeyGen_abe(user);
	if(1)cipher = RSA_Encrypt(RSA_public_key, user.user_key);//如果加密类型为RSA加密
	
	//abe密钥签名
	RSA_Sign(RSA_private_key, cipher.c_str(), buf, sign_length);

	if(1){//RSA加密和签名
		cout<<"密钥及签名生成完毕, 开始返回响应包"<<endl;
		cJSON *data = cJSON_CreateObject();
		cJSON_AddStringToObject(data, "uuid", uuid.c_str());
		char tmp[3];
		string abe_key, sign_data;
		for(int i = 0; i < int(cipher.length()); i++){
			sprintf(tmp, "%02x", (unsigned char) cipher[i]);
            abe_key.append(tmp);
		}
		cJSON_AddStringToObject(data, "abe_key", abe_key.c_str());
        for(int i = 0; i < int(sign_length); i++){
            sprintf(tmp, "%02x", (unsigned char) buf[i]);
            sign_data.append(tmp);
        }
		cJSON_AddStringToObject(data, "kmsSignatureType", "RSA");
		cJSON_AddStringToObject(data, "kmsSignature", sign_data.c_str());
		cJSON_AddItemToObject(response, "data", data);
		
		//发送响应包
		json_str = cJSON_Print(response);
        cout<<"响应包长度:"<<strlen(json_str)<<endl;
        sprintf((char *)json_len_hex, "%x", int(strlen(json_str)));
        SSL_WriteAll (ssl, (char*)json_len_hex, sizeof(json_len_hex));
        SSL_WriteAll (ssl, json_str, strlen(json_str));
		free(json_str);
		data = NULL;
	}
    /* 收尾工作 */
	SSL_shutdown (ssl);
    shutdown (ps_sock->socket_d,2);
	abe_unlock();
	
exit:
	//if(ps_sock)free(ps_sock);
	key = NULL;
	if(request) cJSON_Delete(request);
    if(response) cJSON_Delete(response);
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


int main(void){
	if(abe_init()) sock_init();
	//ShutdownOpenABE();//没有用上
}