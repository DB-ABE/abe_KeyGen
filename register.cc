#include<iostream>
#include<sys/socket.h>
#include<stdlib.h>
#include<string.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<gmssl/socket.h>
// #include<openssl/ssl.h>
// #include<openssl/err.h>

using namespace std;

#define sign_len 256
#define sign_klen 256
#define abe_cklen 256
// register happend when a new user added in the database;

char ip[128]="127.0.0.1";
int port=11111;
int checkuser(char *username, char *attribute){
    return 0;
}
char * sm2_sign(char *key,char *username, char *attribute, char *sign){
    char *tmp=(char*)malloc(sizeof(username)+sizeof(attribute));
    strcpy(tmp, username);
    strcat(tmp, attribute);
//    sign=Sm2(key, sm3(tmp))
    free(tmp);
    return sign;
}

int adduser(char *username, char *attribute){
    return 1;
}

int addpubkey(char *user_hash, char *key){
    return 1;
}
string sm3(char *inbuf){
    string outbuf;
    return outbuf;
}

int sock_connect(char *ip_str, int port){
    int client_sock, connect_flag;;
    struct sockaddr_in client_sockaddr; //定义IP地址结构
	client_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (client_sock == -1)
	{
		printf("socket create error\n");
		return -1;
	}
    memset(&client_sockaddr, 0, sizeof(client_sockaddr));
    memset(&client_sockaddr, 0, sizeof(client_sockaddr));
	client_sockaddr.sin_port = htons(port); //指定一个端口号并将hosts字节型传化成Inet型字节型(大端或或者小端问题)
	client_sockaddr.sin_family = AF_INET; //设置结构类型为TCP/IP
	client_sockaddr.sin_addr.s_addr = inet_addr(ip_str);//将字符串的ip地址转换成int型,客服端要连接的ip地址
	connect_flag = connect(client_sock, (struct sockaddr*) &client_sockaddr, sizeof(client_sockaddr));
	if (connect_flag == -1)
	{
		printf("connect error \n");
		return -1;
	}
    return client_sock;
}
int mysql_generateABEKey(char *username, char *attribute)
{
//    签名
//      与keymanager通信，获取加密私钥
//      私钥存表
    char sign_key[sign_klen], sign[sign_len], abe_ckey[abe_cklen];
    int tmp=checkuser(username, attribute);
    if(tmp){
        //  if username in database
        return 0;
    }

    sm2_sign(sign_key, username, attribute, sign);
    printf("generate sm2_sign_key:%s", sign);
    
    int client_sock;
    client_sock=sock_connect(ip,port);
    printf("connect to KeyGen");

    send(client_sock, sign, sign_len, 0);
    send(client_sock, username, sizeof(username), 0);
    send(client_sock, attribute, sizeof(attribute), 0);
    printf("send username and attribute to Keymanager");

//  adduser in database
    tmp=adduser(username, attribute);
    printf("add user to database");
    if(tmp){
        tmp=addpubkey((char*)sm3(username).c_str(), abe_ckey);
        if(tmp) return 1;
    }
    return 0;

}

int main(){
    mysql_generateABEKey((char*)"zhangsan", (char*)"attr1");
     
    return 0;
}