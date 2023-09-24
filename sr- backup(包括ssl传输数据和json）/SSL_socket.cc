#include "SSL_socket.h"
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

void SSL_ReadAll(SSL *ssl, char *buf, size_t buf_len){
    int i = 0, j = 0;
    while(buf_len > 0){
        j = SSL_read(ssl, buf+i, buf_len);
        i += j; 
        buf_len -=j;
    }
}

void SSL_WriteAll(SSL *ssl, char *buf, size_t buf_len){
    int i = 0, j = 0;
    while(buf_len > 0){
        j = SSL_write(ssl, buf+i, buf_len);
        i += j; 
        buf_len -=j;
    }
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