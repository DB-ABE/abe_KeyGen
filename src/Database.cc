
#include <stdio.h>
#include <iostream>
#include <string>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <mysql/mysql.h>

#include "openssl/crypto.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/rsa.h"      
#include "openssl/crypto.h"

#include "rsa_Crypto.h"
#include "abe_Crypto.h"

#define CACERT "../tmp/cacert.pem"
#define CLIENT_CRT "../tmp/clientcert.pem"
#define CLIENT_KEY "../tmp/client.pem"
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(-2); }
#define SERVER_ADDR "127.0.0.1"
#define PORT 20001
#define abe_test_message "test"

#define SERVER_mode 1
#define CLIENT_mode 0
using namespace std;


const char *RSA_private_key = "../tmp/client.pem";

const char *RSA_public_key = "../tmp/clientcert.pem";
//测试abe密钥，需要保证../abe_key/abe_pp参数
int abe_test(abe_user user, string ct){
    string pt;
    abe_Decrypt(ct, user, pt);
    if(strcpy((char *)pt.c_str(),"test")){
        cout<<"abe密钥验证成功"<<endl;
        return 1;
    }
    else{
        cout<<"abe密钥验证失败，请联系密钥生成方~~!"<<endl;
        return 0;
    }
}
string subreplace(string resource_str, string sub_str, string new_str)
{
    string dst_str = resource_str;
    string::size_type pos = 0;
    while((pos = dst_str.find(sub_str)) != string::npos)   //替换所有指定子串
    {
        dst_str.replace(pos, sub_str.length(), new_str);
    }
    return dst_str;
}

SSL_CTX* InitSSL(char *ca_path, char *client_crt_path, char *client_key_path,int mothflag)//与Keymanager重复
{
    SSL_CTX* ctx=NULL;
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


int mysql_generateABEKey(string username, string attibute){
    char tmp[3];
    string sign_length, abe_ct, abe_pt, cipher, abe_key, sign_data, sign_data_abe;
    abe_user user;
    int sd=0, confd=0;
    unsigned int sign_len;
    SSL* ssl=NULL;
    SSL_CTX* ctx=NULL;
    struct sockaddr_in sa={0};
    char buf[1025]={0}, abe_keybuf[10001]={0};
    const int buf_len=sizeof(buf);
    const int abe_keybuf_len=sizeof(abe_keybuf);
    X509* server_cert=NULL;
    char *str=NULL;
    ctx=InitSSL((char *)CACERT, (char *)CLIENT_CRT, (char *)CLIENT_KEY, CLIENT_mode);
    if(ctx==NULL) return -1;
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
    SSL_get_peer_certificate(ssl);
    server_cert = SSL_get_peer_certificate (ssl);      
    printf ("Keymanager certificate:\n");

    str = X509_NAME_oneline (X509_get_subject_name (server_cert),0,0);
    printf ("/t subject: %s\n", str);
    free (str);

    str = X509_NAME_oneline (X509_get_issuer_name  (server_cert),0,0);
    printf ("/t issuer: %s\n", str);
    free (str);

    X509_free (server_cert);  /*如不再需要,需将证书释放 */

    /* 数据交换开始,用SSL_write,SSL_read代替write,read */
    printf("Begin SSL data exchange\n");

    {   //发送用户名和属性
        SSL_write (ssl, username.c_str(), 1024);
        SSL_write (ssl, attibute.c_str(), 1024); 
        memset (buf,0,1025);

        //进行用户名和属性的签名
        auto ret = RSA_Sign(RSA_private_key, username+attibute, buf, sign_len);
        cout<<"签名数据";
        //以16进制记录签名数据
        for(int i = 0; i < (int)sign_len; i++){
            sprintf(tmp, "%02x", (unsigned char) buf[i]);
            sign_data.append(tmp);
        }
        cout<<sign_data<<endl;
        buf[buf_len-1] = sign_len/RSA_Decrypt_length;
        SSL_write (ssl, buf, 1025); //发送用户属性注册签名给keymanager
        
        //接收keymananger发来的用户abe密钥
        memset (abe_keybuf, 0, abe_keybuf_len);
	    SSL_read (ssl, abe_keybuf, abe_keybuf_len); 
        cout<<"\n接收到abe密钥"<<endl;//接收abe密钥
        //abe密钥记录，16进制
        for (int i = 0; i < abe_keybuf[abe_keybuf_len-1]*RSA_Decrypt_length; i++){
            sprintf(tmp, "%02x", (unsigned char) abe_keybuf[i]);
            abe_key.append(tmp);
        }
        cout<<abe_key<<endl;

        //abe密钥测试,可删
        user.user_id = username;
        user.user_attr = attibute;
        for (int i = 0; i < abe_keybuf[abe_keybuf_len-1]*RSA_Decrypt_length; i++){
            cipher += abe_keybuf[i];
        }
        // char tmpt[5];
        // for(int i = 0; i<abe_key.length()/2; i++){
        //     sprintf(tmpt, "0x%c%c", abe_key[i*2],abe_key[i*2+1]);
        //     cipher += char(stoi(tmpt, 0, 16));
        // }
        // puts("");

        user.user_key=RSA_Decrypt(RSA_private_key, cipher);//RSA_Decrypt(RSA_private_key,buf)
        abe_Encrypt(abe_test_message, "attr1 and attr2", abe_ct);
        abe_Decrypt(abe_ct, user, abe_pt);
        
        //接收keymanager的abe密钥签名，防止抵赖
        memset (buf,0,1025);
	    SSL_read (ssl, buf, 1025); 
        printf("接收到abe签名信息:\n");//接收abe密钥签名
        for(int i = 0; i < buf[buf_len-1]*RSA_Decrypt_length; i++){
            sprintf(tmp, "%02x", (unsigned char) buf[i]);
            sign_data_abe.append(tmp);
        }
        cout<<sign_data_abe<<endl;
        //abe密钥签名认证,可删
        ret = RSA_Verify(RSA_public_key, cipher.c_str(), buf);
	    if(ret!=1){
            cout<<"验签失败，请数据库传输正确的签名数据~~。"<<endl;
            goto exit;
	    }
	    cout<<"验证签名成功"<<endl;
        
    }
    /* 收尾工作 */
    SSL_shutdown (ssl);  /* send SSL/TLS close_notify */
    shutdown (sd,2);
    //将两个签名与abe密钥存入数据库，username, attibute, abe_key.c_str(), sign_data，sign_data_user; 

exit:
    if(ctx) SSL_CTX_free(ctx);
    if(ssl) SSL_free (ssl);
    return 1;
}
int main()
{
    //首先进行用户的检索，检查用户是否已经拥有密钥
    MYSQL *conn=NULL;
    MYSQL_RES *res=NULL;
    MYSQL_ROW row;
    int column;
    const char *server = "10.12.153.17";
    const char *user = "Database";
    const char *password = "123456";
    const char *database = "TPCC";
    unsigned int port = 12348;
    conn = mysql_init(NULL);
    /* 连接数据库 */
    if (!mysql_real_connect(conn, server, user, password, database, port, NULL, 0)) {
        cout << mysql_error(conn);
        goto exit;
    }
    cout<<"user: "<<user<<"成功连接至数据库"<<endl;
    mysql_query(conn, "show databases");
    res = mysql_store_result(conn);
    column = mysql_num_fields(res);
    while((row = mysql_fetch_row(res))){
        for(int i = 0; i<column; i++){
            cout<<row[i]<<"\t";
        }
        cout<<endl;
    }

    mysql_generateABEKey("lisi", "|attr1|attr2|attr3 = 3|Date = March 20, 2022");
    
exit:
    if(conn)mysql_close(conn);
    if(res)mysql_free_result(res);
    return 0;
}
