
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "openssl/crypto.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/rsa.h"      
#include "openssl/crypto.h"


#define CACERT "../tmp/ca.cert"
#define SERVER_CRT "../tmp/server.cert"
#define SERVER_KEY "../tmp/server.pem"
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(-2); }
#define SERVER_ADDR "127.0.0.1"
#define PORT 20001
#define SERVER_mode 1
#define CLIENT_mode 0

SSL_CTX* InitSSL(char *ca_path,char *client_crt_path,char *client_key_path,int mothflag)
{
    SSL_CTX* ctx=NULL;
    SSL_METHOD *meth;
    int status;
 
    /* * 算法初始化 * */   
    SSL_library_init();
    // 加载SSL错误信息
    SSL_load_error_strings();
 
    // 添加SSL的加密/HASH算法
    SSLeay_add_ssl_algorithms();
    
    /*采用什么协议(SSLv2/SSLv3/TLSv1)在此指定*/
    if(mothflag)
        meth = (SSL_METHOD *)TLSv1_2_server_method();
    else
        meth = (SSL_METHOD *)TLSv1_2_client_method();
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

int main()
{
    int sd=0;
    int confd=0;
    SSL* ssl=NULL;
    SSL_CTX* ctx=NULL;
    char *str=NULL;
    X509* server_cert=NULL;
    struct sockaddr_in sa_serv={0};
    struct sockaddr_in sa_cli={0};
    unsigned char buf[300]={0};
    ctx=InitSSL(CACERT,SERVER_CRT,SERVER_KEY,SERVER_mode);
    if(ctx==NULL) return -1;

    /* 指定加密器类型 */
    // SSL_CTX_set_cipher_list (ctx, "ECDHE-RSA-AES256-SHA");
    // SSL_CTX_set_mode (ctx, SSL_MODE_AUTO_RETRY);

    /*以下是正常的TCP socket建立过程 .............................. */
    printf("Begin tcp socket...\n");

    sd = socket (AF_INET, SOCK_STREAM, 0);  

    sa_serv.sin_family      = AF_INET;
    sa_serv.sin_addr.s_addr = inet_addr("127.0.0.1");
    sa_serv.sin_port        = htons (PORT);         
    
    int opt = 1;
    if(setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        fprintf(stderr,"[tskIpRev]: setsockopt(SO_REUSEADDR) error\n");
        return 0;
    }
    
    bind(sd, (struct sockaddr*) &sa_serv,sizeof (sa_serv));

    /*接受TCP链接*/
    listen (sd, 5);                   
 
    socklen_t client_len = sizeof(sa_cli);
    sd = accept (sd, (struct sockaddr*) &sa_cli, &client_len);

    /* TCP 链接已建立.开始 SSL 握手过程.......................... */
    printf("Begin SSL negotiation \n");

    /*申请一个SSL套接字*/
    ssl = SSL_new (ctx);                        
    if(ssl <= 0)
    {
        printf("Error creating SSL new \n");
        goto exit;
    }

    /*绑定读写套接字*/
    SSL_set_fd (ssl, sd);
    SSL_accept (ssl);               
    printf("链接已建立.开始 SSL 握手过程 \n");

    /*打印所有加密算法的信息(可选)*/
    printf ("SSL connection using %s\n", SSL_get_cipher (ssl));

    /*得到服务端的证书并打印些信息(可选) */
    server_cert = SSL_get_peer_certificate (ssl);      
    printf ("Server certificate:\n");

    str = X509_NAME_oneline (X509_get_subject_name (server_cert),0,0);
    printf ("/t subject: %s\n", str);
    free (str);

    str = X509_NAME_oneline (X509_get_issuer_name  (server_cert),0,0);
    printf ("/t issuer: %s\n", str);
    free (str);

    X509_free (server_cert);  /*如不再需要,需将证书释放 */

    /* 数据交换开始,用SSL_write,SSL_read代替write,read */
    printf("Begin SSL data exchange\n");

    while(1)
    {
        memset (buf,0,300);
        int ret = SSL_read (ssl, buf, sizeof(buf)); 
        if(ret <= 0 )
            break;
        printf ("Got %d chars:'%s'\n", ret, buf);
    }
    SSL_shutdown (ssl);  /* send SSL/TLS close_notify */
    /* 收尾工作 */
    shutdown (sd,2);

exit:
    if(ctx) SSL_CTX_free(ctx);
    if(ssl) SSL_free (ssl);
    return 0;
}
