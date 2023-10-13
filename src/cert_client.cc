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

const char * ca_path = "../tmp/cacert.pem";

int cert_generate(const char *country, const char *Organization, const char *Common_Name){
    int confd = 0;
    char crt_len[5] = {0};
    char *dataStr = NULL;
    RSA* rsa = NULL;
    X509_REQ* req = NULL;
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
    SSL_CTX *ctx = NULL;

    //ctx初始化代码块
    {
		SSL_METHOD *meth;
		/* * 算法初始化 * */   
		SSL_library_init();
		// 加载SSL错误信息
		SSL_load_error_strings();
	
		// 添加SSL的加密/HASH算法
		SSLeay_add_ssl_algorithms();
		meth = (SSL_METHOD *)TLS_client_method();
		/* 创建SSL会话环境 */
		ctx = SSL_CTX_new (meth);                    
		if(ctx == NULL)
		{
			printf ("SSL_CTX_new error\n");
			return 1;
		}
		// /*验证与否,是否要验证对方*/
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);   
		// /*若验证对方,则放置CA证书*/
		SSL_CTX_load_verify_locations(ctx, ca_path, NULL); 
	}

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
    {
        char *str = NULL;
        X509 *server_cert = NULL;
        /*打印所有加密算法的信息(可选)*/
        printf ("SSL connection using %s\n", SSL_get_cipher (ssl));
        /*得到服务端的证书并打印些信息(可选) */
        server_cert = SSL_get_peer_certificate (ssl);      
        printf ("server certificate:\n");
        if(server_cert == NULL){
            printf ("server certificate error:\n");
            goto exit;
        }

        str = X509_NAME_oneline (X509_get_subject_name (server_cert),0,0);
        printf ("/t subject: %s\n", str);
        free (str);

        str = X509_NAME_oneline (X509_get_issuer_name  (server_cert),0,0);
        printf ("/t issuer: %s\n", str);
        free (str);

        X509_free (server_cert);  /*如不再需要,需将证书释放 */
    }
    /* 数据交换开始,用SSL_write,SSL_read代替write,read */
    printf("Begin SSL data exchange\n");


    // 创建 RSA 密钥对
    {
        BIGNUM *bne = BN_new();;
        int ret = BN_set_word(bne, 65537);
        if(ret != 1){
            goto exit;
        }
        rsa = RSA_new();
        ret = RSA_generate_key_ex(rsa, 2048, bne, NULL);
        if(ret != 1){
            BN_free(bne);
            goto exit;
        }
        BN_free(bne);
        // rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
        // if (rsa == NULL) {
        //     perror("RSA 密钥对生成失败");
        //     goto exit;
        // }
    }

    // 创建 X509_REQ 对象
    req = X509_REQ_new();
    if (req == NULL) {
        perror("X509_REQ 对象创建失败");
        RSA_free(rsa);
        goto exit;
    }

    //代码块：证书请求信息
    {
        // 设置证书请求版本
        X509_REQ_set_version(req, 0);
        // 设置证书请求持有者信息
        X509_NAME* name = X509_NAME_new();
        X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)country, -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)Organization, -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)Common_Name, -1, -1, 0);
        X509_REQ_set_subject_name(req, name);
        X509_NAME_free(name);
    }

    //代码块:证书公钥设置
    {
        // 设置证书请求公钥
        EVP_PKEY* pkey = EVP_PKEY_new();
        EVP_PKEY_assign_RSA(pkey, rsa);
        X509_REQ_set_pubkey(req, pkey);

        // 签名证书请求
        if (!X509_REQ_sign(req, pkey, EVP_sha512())) {
            perror("证书请求签名失败");
            EVP_PKEY_free(pkey);
            goto exit;
        }
        EVP_PKEY_free(pkey);
    }
    
    //代码块：证书请求导出字符串
    {
        // 导出为字符类型
        BIO *bio = BIO_new(BIO_s_mem());
        if (!bio) {
            fprintf(stderr, "无法创建BIO对象\n");
            goto exit;
        }

        if (PEM_write_bio_X509_REQ(bio, req) == 0) {
            fprintf(stderr, "无法导出证书请求\n");
            BIO_free(bio);
            goto exit;
        }

        char *csrData;
        long csrDataLen = BIO_get_mem_data(bio, &csrData);
        if (csrDataLen <= 0) {
            fprintf(stderr, "无法获取导出的证书请求数据\n");
            BIO_free(bio);
            goto exit;
        }
        
        char *DataString = (char *) malloc(1 + sizeof(char) * csrDataLen);
        sprintf(DataString, "%.*s", int(csrDataLen), csrData);
        // 打印导出的证书请求数据
        printf("导出的证书请求数据:\n%s\n", DataString);
        //free(csrData);
        sprintf((char *)crt_len, "%02x", int(csrDataLen));
        SSL_WriteAll(ssl, crt_len, sizeof(crt_len));
        SSL_WriteAll(ssl, DataString, csrDataLen + 1);
        free(DataString);
        BIO_free(bio);
        bio = NULL;
        X509_REQ_free(req);
        req = NULL;
    }

    //代码块：接收来自KMS的证书
    {
        char *suffix = (char *)malloc(5 + strlen(Common_Name) * sizeof(char));//文件名；
        sprintf(suffix, "%s.pem", Common_Name);
        X509* cert_new = NULL; FILE *certFile = NULL;
        SSL_ReadAll(ssl, crt_len, sizeof(crt_len));
		int dataLen = stoi((const char*)crt_len, 0, 16);
		dataStr = (char *)malloc(1 + sizeof(char) * dataLen);
		SSL_ReadAll(ssl, dataStr, dataLen + 1);
        printf("证书字符串:%s\n", dataStr);
        BIO* bio_certString = BIO_new_mem_buf(dataStr, -1);
        if (bio_certString == NULL) {
            // 处理加载失败的情况
            free(dataStr);
            goto exit;
        }
        
        // 从内存中读取 X.509 证书
        cert_new = PEM_read_bio_X509(bio_certString, NULL, NULL, NULL);
        free(dataStr);
        // 释放 BIO 对象
        BIO_free(bio_certString);
        certFile = fopen(suffix, "wb");
        free(suffix); suffix = NULL;
        if (!certFile) {
            if(cert_new){
                X509_free(cert_new);
            }
			fprintf(stderr, "无法打开证书文件\n");
			goto exit;
		}
        if (PEM_write_X509(certFile, cert_new) != 1) {
			// 处理写入失败的情况
            if(cert_new){
                X509_free(cert_new);
            }
			fclose(certFile);
			goto exit;
		}
        fclose(certFile);
        if (cert_new == NULL) {
            // 处理读取失败的情况
            cout<<"证书生成失败,程序退出"<<endl;
        }
        else cout<<"证书生成成功,程序退出"<<endl;
        // 清理证书对象
        if(cert_new)X509_free(cert_new);
    }
exit:
    SSL_shutdown (ssl);
	SSL_free (ssl);
    SSL_CTX_free(ctx);
    if(req) X509_REQ_free(req);
    // 清理资源
    return 0;
}

int main(){
    cert_generate("CN", "hust", "zhangsan");
    return 0;
}
//g++ -o cert_client -std=c++11 -pthread -Wall -g -O2 -DSSL_LIB_INIT  -I/usr/local/include -L/usr/local/lib cert_client.cc -lcrypto -lssl -lcjson -ldl -fsanitize=address
