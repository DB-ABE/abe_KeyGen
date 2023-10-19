#include "SSL_socket.h"
#include <stdio.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <string.h>
#include "cjson/cJSON.h"
// 将字符串转换为Base64编码
char *base64Encode(const unsigned char *input, int length)
{
    BIO *bio = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new(BIO_s_mem());
    bio = BIO_push(bio, bmem);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input, length);
    BIO_flush(bio);

    char *base64Data;
    long base64Length = BIO_get_mem_data(bmem, &base64Data);

    char *base64String = (char *)malloc(base64Length + 1);
    if (base64String == NULL)
    {
        perror("内存分配失败");
        BIO_free_all(bio);
        return NULL;
    }

    memcpy(base64String, base64Data, base64Length);
    base64String[base64Length] = '\0';

    BIO_free_all(bio);
    return base64String;
}

// 将base64转换为字符串
unsigned char *base64Decode(const char *input, int length, int *outputLength)
{
    BIO *bio = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new_mem_buf(input, length);
    bio = BIO_push(bio, bmem);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    unsigned char *output = (unsigned char *)malloc(length + 1);
    if (output == NULL)
    {
        perror("内存分配失败");
        BIO_free_all(bio);
        return NULL;
    }

    *outputLength = BIO_read(bio, output, length);
    BIO_free_all(bio);
    output[*outputLength] = '\0';
    return output;
}

void SSL_ReadAll(SSL *ssl, char *buf, size_t buf_len)
{
    int i = 0, j = 0;
    while (buf_len > 0)
    {
        j = SSL_read(ssl, buf + i, buf_len);
        i += j;
        buf_len -= j;
    }
}

void SSL_WriteAll(SSL *ssl, char *buf, size_t buf_len)
{
    int i = 0, j = 0;
    while (buf_len > 0)
    {
        j = SSL_write(ssl, buf + i, buf_len);
        i += j;
        buf_len -= j;
    }
}

bool check_cert(std::string cert_pwd)
{
    if (access(cert_pwd.c_str(), F_OK) == 0)
    {
        std::cout << "用户的证书存在, 可以继续~~" << std::endl;
        return true;
    }
    std::cout << "该用户不存在证书" << std::endl;
    return false;
}

void show_SSL(SSL *ssl)
{
    /*得到服务端的证书并打印些信息(可选) */
    X509 *server_cert = SSL_get_peer_certificate(ssl);
    printf("get SSL certificate:\n");
    char *str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
    printf("/t subject: %s\n", str);
    free(str);
    str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
    printf("/t issuer: %s\n", str);
    free(str);
    X509_free(server_cert); /*如不再需要,需将证书释放 */
                            /*打印所有加密算法的信息(可选)*/
    printf("SSL connection using %s\n", SSL_get_cipher(ssl));
}

SSL_CTX *InitSSL(char *ca_path, char *client_crt_path,
                 char *client_key_path, int mothflag) // 与Keymanager重复
{
    SSL_CTX *ctx = NULL;
    SSL_METHOD *meth;
    /* * 算法初始化 * */
    SSL_library_init();
    // 加载SSL错误信息
    SSL_load_error_strings();

    // 添加SSL的加密/HASH算法
    SSLeay_add_ssl_algorithms();

    /*采用什么协议(SSLv2/SSLv3/TLSv1)在此指定*/
    if (mothflag)
        meth = (SSL_METHOD *)TLS_server_method();
    else
        meth = (SSL_METHOD *)TLS_client_method();
    /* 创建SSL会话环境 */
    ctx = SSL_CTX_new(meth);
    if (ctx == NULL)
    {
        printf("SSL_CTX_new error\n");
        return NULL;
    }

    // /*验证与否,是否要验证对方*/
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    // /*若验证对方,则放置CA证书*/
    SSL_CTX_load_verify_locations(ctx, ca_path, NULL);

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
    // SSL_CTX_set_default_passwd_cb_userdata(ctx, pw);

    /*调用了以上两个函数后,检验一下自己的证书与私钥是否配对*/
    if (!SSL_CTX_check_private_key(ctx))
    {
        printf("SSL_CTX_check_private_key error\n");
        goto exit;
    }
    return ctx;

exit:
    if (ctx)
        SSL_CTX_free(ctx);
    return NULL;
}

void SSL_Json_get(SSL *ssl, std::string &uuid, std::string &username, std::string &attibute,
                  std::string &sign_type, std::string &user_sign, int &code)
{
    // begin json transportion
    char json_len_hex[5];
    SSL_ReadAll(ssl, (char *)json_len_hex, sizeof(json_len_hex));
    int json_len = std::stoi((const char *)json_len_hex, 0, 16);
    std::cout << "接收到请求包长度:" << json_len << std::endl;
    char *json_str = (char *)malloc(sizeof(char) * json_len + 1);
    SSL_ReadAll(ssl, json_str, json_len);
    json_str[json_len] = '\0';
    cJSON *request = cJSON_Parse(json_str);
    free(json_str);
    cJSON *key = cJSON_GetObjectItem(request, "uuid"); // 提取uuid
    uuid.assign(key->valuestring);
    std::cout << "uuid: " << key->valuestring << std::endl;
    key = cJSON_GetObjectItem(request, "type"); // 提取注册类型
    code = key->valueint;

    key = cJSON_GetObjectItem(request, "username"); // 提取user_id
    username.assign(key->valuestring);
    std::cout << "username_json: " << key->valuestring << std::endl;
    key = cJSON_GetObjectItem(request, "attribute"); // 提取uer_attribute
    attibute.assign(key->valuestring);
    std::cout << "attribute_json: " << key->valuestring << std::endl;
    key = cJSON_GetObjectItem(request, "dbSignature");
    printf("Got signature: of %s\n", username.c_str()); // 提取并转换签名信息

    int ret = 0;
    char *base64String = (char *)base64Decode(key->valuestring, strlen(key->valuestring), &ret);
    if (base64String == NULL)
    {
        std::cout << "签名base解码失败" << std::endl;
    }
    else
    {
        user_sign.assign(base64String, ret);
        free(base64String);
        base64String = NULL;
    }
    key = cJSON_GetObjectItem(request, "dbSignatureType"); // 提取签名类型
    sign_type.assign(key->valuestring);
}
void SSL_Json_write(SSL *ssl, char *json_str)
{
    char json_len_hex[5];
    sprintf((char *)json_len_hex, "%04x", int(strlen(json_str)));
    SSL_WriteAll(ssl, (char *)json_len_hex, sizeof(json_len_hex));
    SSL_WriteAll(ssl, json_str, strlen(json_str));
}

void SSL_response_error(SSL *ssl, std::string uuid, const char *msg, int error_code)
{
    cJSON *response = cJSON_CreateObject();
    cJSON_AddNumberToObject(response, "code", error_code);
    cJSON_AddStringToObject(response, "msg", msg);
    cJSON *data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "uuid", uuid.c_str());
    cJSON_AddItemToObject(response, "data", data);
    char *json_str = cJSON_Print(response);
    std::cout << "abe_keygen_error: 响应包长度:" << strlen(json_str) << std::endl;
    SSL_Json_write(ssl, json_str);
    free(json_str);
    data = NULL;
    cJSON_Delete(response);
}

void SSL_response_ok(SSL *ssl, std::string uuid, const char *msg, const std::string cipher, unsigned char *RSA_sign_buf, unsigned int sign_length, int ok_code)
{
    cJSON *response = cJSON_CreateObject();
    // RSA加密和签名
    cJSON *data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "uuid", uuid.c_str());
    std::string abe_key, sign_data;
    cJSON_AddNumberToObject(response, "code", 0);
    cJSON_AddStringToObject(response, "msg", "用户信息核验成功, 生成abe_密钥");
    char *base64String = base64Encode((const unsigned char *)cipher.c_str(), cipher.length());
    abe_key.assign(base64String);
    cJSON_AddStringToObject(data, "abe_key", base64String);
    free(base64String);

    base64String = base64Encode((const unsigned char *)RSA_sign_buf, sign_length);
    cJSON_AddStringToObject(data, "kmsSignatureType", "RSA");
    cJSON_AddStringToObject(data, "kmsSignature", base64String);
    cJSON_AddItemToObject(response, "data", data);
    free(base64String);
    base64String = NULL;
    // 发送响应包
    char *json_str = cJSON_Print(response);
    std::cout << "响应包长度:" << strlen(json_str) << std::endl;
    SSL_Json_write(ssl, json_str);
    free(json_str);
    data = NULL;
}

void SSL_Shut(SSL *ssl, SSL_CTX *ctx){
    if (ctx)
		SSL_CTX_free(ctx);
	if (ssl)
	{
		SSL_shutdown(ssl);
		SSL_free(ssl);
	} /* send SSL/TLS close_notify */
}