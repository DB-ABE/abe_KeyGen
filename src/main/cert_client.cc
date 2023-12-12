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

#include "Config.h"
#include "SSL_socket.h"
#define SERVER_ADDR "127.0.0.1"
#define PORT 20000
using namespace std;

static string ca_cert;

int cert_generate(const char *country, const char *Organization, const char *Common_Name){
    int confd = 0;
    /*以下是正常的TCP socket建立过程 .............................. */
    printf("Begin tcp socket...\n");
    int sd = socket (AF_INET, SOCK_STREAM, 0);       
    if(sd <= 0)
    {
        perror("socket");
        return 1;
    }
    struct sockaddr_in sa={0};
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = inet_addr(SERVER_ADDR);   /* Server IP */
    sa.sin_port        = htons(PORT);          /* Server Port number */
    confd = connect(sd, (struct sockaddr*)&sa, sizeof(sa)); 
    if(confd < 0)
    {
        printf("connect error=%d\n",confd);
        return 1;
    }
    /* TCP 链接已建立.开始 SSL 握手过程.......................... */
    //ctx初始化
    SSL_CTX *ctx = cert_SSL_Init(NULL, NULL, ca_cert.c_str(), 0);
    SSL* ssl = SSL_new(ctx);
    if(ssl <= 0)
    {
        printf("Error creating SSL new \n");
        SSL_CTX_free(ctx);
        return 1;
    }

    /*绑定读写套接字*/
    SSL_set_fd (ssl, sd);
    SSL_connect (ssl);               
    printf("链接已建立.开始 SSL 握手过程 \n");

    //客户端认证KMS证书代码块
    show_SSL(ssl);
    /* 数据交换开始,用SSL_write,SSL_read代替write,read */
    printf("Begin SSL data exchange\n");

    // 创建 RSA 密钥对
    RSA *rsa = generate_prikey(65537, 2048, Common_Name, "./tmp/");
    if(!rsa){
        SSL_Shut(ssl, NULL, NULL, NULL, ctx);
        return -1;
    }
    // 创建 X509_REQ 对象
    X509_REQ *req = X509_REQ_new();
    if (req == NULL) {
        perror("X509_REQ 对象创建失败");
        RSA_free(rsa);
        SSL_Shut(ssl, NULL, NULL, req, ctx);
        return -1;
    }
    
    if(!info_csr_Set(req, rsa, country, Organization, Common_Name)){
        SSL_Shut(ssl, NULL, NULL, req, ctx);
        return -1;
    }
    //代码块：证书请求导出字符串
    if(!SSL_csr_Write(ssl, req)){
        SSL_Shut(ssl, NULL, NULL, req, ctx);
        return -1;
    }
    X509_REQ_free(req);
    req = NULL;
    //接收来自KMS的证书
    if(!SSL_cert_Read(ssl, Common_Name, "./cert/user/")) {
        perror("证书接收异常");
        return -1;
    }
    SSL_Shut(ssl, NULL, NULL, req, ctx);
    // 清理资源
    return 0;
}

int main(){
    json config = loadConfiguration("./conf/Config.json");
    ca_cert = getConfigString(config, "CA_cert");
    cert_generate("CN", "hust", "zhangsan");
    return 0;
}
//g++ -o cert_client -std=c++11 -pthread -Wall -g -O2 -DSSL_LIB_INIT  -I/usr/local/include -L/usr/local/lib cert_client.cc -lcrypto -lssl -lcjson -ldl -fsanitize=address
