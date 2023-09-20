
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


#define CACERT "../cert/ca.crt"
#define CLIENT_CRT "../cert/client.crt"
#define CLIENT_KEY "../cert/client.key"
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(-2); }
#define SERVER_ADDR "172.16.39.197"
#define PORT 20001

#include"abe_Crypto.h"
#include <cassert>

#define SERVER_mode 1
#define CLIENT_mode 0

void test_abe(){
     InitializeOpenABE();

    cout << "Testing CP-ABE context" << endl;

    OpenABECryptoContext cpabe("CP-ABE");

    string ct, pt1 = "hello world!", pt2;

    cpabe.generateParams();

    cpabe.keygen("|attr1|attr2", "key0");

    cpabe.encrypt("attr1 and attr2", pt1, ct);

    bool result = cpabe.decrypt("key0", ct, pt2);

    assert(result && pt1 == pt2);

    cout << "Recovered message: " << pt2 << endl;

    ShutdownOpenABE();
}
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
    test_abe();
    int sd=0;
    int confd=0;
    SSL* ssl=NULL;
    SSL_CTX* ctx=NULL;
    struct sockaddr_in sa={0};
    unsigned char buf[300]={0};
    X509* server_cert=NULL;
    char *str=NULL;
    ctx=InitSSL(CACERT,CLIENT_CRT,CLIENT_KEY,CLIENT_mode);
    if(ctx==NULL) goto exit;
    /* 指定加密器类型 */
    SSL_CTX_set_cipher_list (ctx, "ECDHE-RSA-AES256-SHA");
    SSL_CTX_set_mode (ctx, SSL_MODE_AUTO_RETRY);

    /*以下是正常的TCP socket建立过程 .............................. */
    printf("Begin tcp socket...\n");

    sd= socket (AF_INET, SOCK_STREAM, 0);       
    if(sd <= 0)
    {
        perror("socket");
        goto exit;
    }
    
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = inet_addr(SERVER_ADDR);   /* Server IP */
    sa.sin_port        = htons(PORT);          /* Server Port number */
    confd = connect(sd, (struct sockaddr*)&sa, sizeof(sa)); 
    if(confd < 0)
    {
        printf("connect error=%d\n",confd);
        goto exit;
    }


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
    SSL_connect (ssl);               
    printf("链接已建立.开始 SSL 握手过程 \n");


    /*打印所有加密算法的信息(可选)*/
    printf ("SSL connection using %s\n", SSL_get_cipher (ssl));
    /*得到服务端的证书并打印些信息(可选) */
    SSL_get1_peer_certificate(ssl);
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
        scanf("%s", buf);
        int ret = SSL_write (ssl, buf, sizeof(buf)); 
        memset (buf, 0, sizeof(buf));
    }
    SSL_shutdown (ssl);  /* send SSL/TLS close_notify */
    /* 收尾工作 */
    shutdown (sd,2);
exit:
    if(ctx) SSL_CTX_free(ctx);
    if(ssl) SSL_free (ssl);
    return 0;
}
