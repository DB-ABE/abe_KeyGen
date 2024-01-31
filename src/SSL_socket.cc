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

    // /*验证与否,是否要验证对方*/
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    // /*若验证对方,则放置CA证书*/
    SSL_CTX_load_verify_locations(ctx, ca_path, NULL);

    /*加载自己的证书*/
    if (SSL_CTX_use_certificate_file(ctx, client_crt_path, SSL_FILETYPE_PEM) <= 0)
    {
        printf("SSL_CTX_use_certificate_file error\n");
        if (ctx)
            SSL_CTX_free(ctx);
        return NULL;
    }
    /*加载自己的私钥,以用于签名*/
    if (SSL_CTX_use_PrivateKey_file(ctx, client_key_path, SSL_FILETYPE_PEM) <= 0)
    {
        printf("SSL_CTX_use_PrivateKey_file error\n");
        if (ctx)
            SSL_CTX_free(ctx);
        return NULL;
    }

    // 设置证书私钥文件的密码
    // SSL_CTX_set_default_passwd_cb_userdata(ctx, pw);
    return ctx;
}

void SSL_Json_Get(SSL *ssl, std::string &uuid, std::string &username, std::string &attibute,
                  std::string &sign_type, std::string &user_sign, int &code)
{
    // begin json transportion
    char json_len_hex[5] = {0};
    SSL_ReadAll(ssl, (char *)json_len_hex, sizeof(json_len_hex) - 1);
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
    if (base64String)
    {
        user_sign.assign(base64String, ret);
        free(base64String);
        base64String = NULL;
    }
    key = cJSON_GetObjectItem(request, "dbSignatureType"); // 提取签名类型
    sign_type.assign(key->valuestring);
    cJSON_Delete(request);
}

void SSL_Json_Write(SSL *ssl, char *json_str)
{
    char json_len_hex[5] = {0};
    sprintf((char *)json_len_hex, "%04x", int(strlen(json_str)));
    SSL_WriteAll(ssl, (char *)json_len_hex, sizeof(json_len_hex) - 1);
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
    SSL_Json_Write(ssl, json_str);
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
    cJSON_AddStringToObject(response, "msg", msg);
    char *base64String = base64Encode((const unsigned char *)cipher.c_str(), cipher.length());
    abe_key.assign(base64String);
    cJSON_AddStringToObject(data, "abekey", base64String);
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
    SSL_Json_Write(ssl, json_str);
    free(json_str);
    data = NULL;
    cJSON_Delete(response);
}

void SSL_Shut(SSL *ssl, BIO *bio_req, char *dataStr, X509_REQ *req, SSL_CTX *ctx)
{
    if (ssl)
    {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    } /* send SSL/TLS close_notify */

    if (dataStr)
        free(dataStr);
    if (bio_req)
        BIO_free(bio_req); /*free cert_req*/

    if (req)
        X509_REQ_free(req); /*free req in client*/

    if (ctx)
        SSL_CTX_free(ctx); /*free req in client*/
}

EVP_PKEY *SSL_PKEY_Read(const char *key_path)
{
    EVP_PKEY *Key;
    FILE *caKeyFile = fopen(key_path, "rb");
    if (!caKeyFile)
    {
        fprintf(stderr, "无法打开 KMS 的私钥文件\n");
        return NULL;
    }
    Key = PEM_read_PrivateKey(caKeyFile, NULL, NULL, NULL);
    fclose(caKeyFile);
    return Key;
}

SSL_CTX *cert_SSL_Init(const char *server_cert_path, const char *server_key_path, const char *ca_path, bool C_S_flag)
{
    SSL_CTX *ctx = NULL;
    SSL_METHOD *meth;
    /* * 算法初始化 * */
    SSL_library_init();
    // 加载SSL错误信息
    SSL_load_error_strings();

    // 添加SSL的加密/HASH算法
    SSLeay_add_ssl_algorithms();
    if (C_S_flag)
        meth = (SSL_METHOD *)TLS_server_method();
    else
        meth = (SSL_METHOD *)TLS_client_method();
    /* 创建SSL会话环境 */
    ctx = SSL_CTX_new(meth);

    if (C_S_flag)
    {
        // /*验证与否,是否要验证对方*/
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        /*加载自己的证书*/
        if (SSL_CTX_use_certificate_file(ctx, server_cert_path, SSL_FILETYPE_PEM) <= 0)
        {
            printf("SSL_CTX_use_certificate_file error\n");
            if (ctx)
                SSL_CTX_free(ctx);
            return NULL;
        }
        /*加载自己的私钥,以用于签名*/
        if (SSL_CTX_use_PrivateKey_file(ctx, server_key_path, SSL_FILETYPE_PEM) <= 0)
        {
            printf("SSL_CTX_use_PrivateKey_file error\n");
            if (ctx)
                SSL_CTX_free(ctx);
            return NULL;
        }
        // 设置证书私钥文件的密码
        // SSL_CTX_set_default_passwd_cb_userdata(ctx, pw);

        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        // /*若验证对方,则放置CA证书*/
        SSL_CTX_load_verify_locations(ctx, ca_path, NULL);
        return ctx;
    }

    return ctx;
}

X509 *cert_Gen(X509_REQ *req_new, EVP_PKEY *KMS_key)
{
    X509 *cert = X509_new();

    // 设置证书版本号
    X509_set_version(cert, 2); // 版本号为2代表X.509 v3

    // 设置证书序列号
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);

    // 设置证书有效期
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L); // 有效期为1年

    // 设置证书主题
    X509_set_subject_name(cert, X509_REQ_get_subject_name(req_new));

    // 设置证书颁发者
    X509_set_issuer_name(cert, X509_REQ_get_subject_name(req_new));

    // 设置证书公钥
    EVP_PKEY *pkey_req = X509_REQ_get_pubkey(req_new);
    X509_set_pubkey(cert, pkey_req);
    EVP_PKEY_free(pkey_req);
    pkey_req = NULL;

    // 签名证书
    if (!X509_sign(cert, KMS_key, EVP_sha512()))
    {
        X509_free(cert);
        fprintf(stderr, "无法签名证书\n");
        return NULL;
    }
    return cert;
}

void cert_Save(X509 *cert, const char *pwd)
{
    X509_NAME_ENTRY *entry = NULL;
    ASN1_STRING *cnData = NULL;
    char *cnStr = NULL;
    FILE *certFile = NULL;
    // 获取证书主题
    X509_NAME *subject = X509_get_subject_name(cert);
    // 查找 Common Name (CN) 字段
    int cnIndex = X509_NAME_get_index_by_NID(subject, NID_commonName, -1);
    // 获取 CN 字段的值
    entry = X509_NAME_get_entry(subject, cnIndex);
    cnData = X509_NAME_ENTRY_get_data(entry);
    // 将 CN 字段的值转换为 C 字符串
    cnStr = (char *)ASN1_STRING_get0_data(cnData);
    // 将证书保存到文件
    certFile = fopen((pwd + std::string(cnStr) + "_cert.pem").c_str(), "wb");

    PEM_write_X509(certFile, cert);
    fclose(certFile);
}

X509 *cert_from_str(BIO *bio_req, EVP_PKEY *KMS_key)
{
    X509_REQ *req_new = PEM_read_bio_X509_REQ(bio_req, NULL, NULL, NULL);

    // 创建证书
    X509 *cert = cert_Gen(req_new, KMS_key);
    X509_REQ_free(req_new);

    // 保存证书
    cert_Save(cert);
    return cert;
}

void SSL_cert_Write(SSL *ssl, X509 *cert)
{
    // 将证书转换为字符串
    BIO *bio_cert = BIO_new(BIO_s_mem());

    PEM_write_bio_X509(bio_cert, cert);

    char *certStr;
    long certSize = BIO_get_mem_data(bio_cert, &certStr);
    char *DataString_new = (char *)malloc(1 + sizeof(char) * certSize);
    sprintf(DataString_new, "%.*s", int(certSize), certStr);
    printf("证书字符串：\n%s\n", DataString_new);

    char crt_len[5] = {0};
    sprintf((char *)crt_len, "%04x", int(certSize));
    SSL_WriteAll(ssl, crt_len, sizeof(crt_len) - 1);
    SSL_WriteAll(ssl, DataString_new, certSize + 1);
    BIO_free(bio_cert);
    bio_cert = NULL;
    free(DataString_new);
}

//
RSA *generate_prikey(unsigned long word, int bits, const char *Common_Name, const char *pwd)
{
    BIGNUM *bne = BN_new();
    ;
    BN_set_word(bne, 65537);
    RSA *rsa = RSA_new();
    RSA_generate_key_ex(rsa, 2048, bne, NULL);
    if (Common_Name)
    {
        FILE *file = fopen((pwd + std::string(Common_Name) + "_prikey.pem").c_str(), "w");
        PEM_write_RSAPrivateKey(file, rsa, NULL, NULL, 0, NULL, NULL);
        fclose(file);
    }
    BN_free(bne);
    return rsa;
}

bool info_csr_Set(X509_REQ *req, RSA *rsa, const char *country,
                  const char *Organization, const char *Common_Name)
{
    // 设置证书请求版本
    X509_REQ_set_version(req, 0);
    // 设置证书请求持有者信息
    X509_NAME *name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)country, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)Organization, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)Common_Name, -1, -1, 0);
    X509_REQ_set_subject_name(req, name);
    X509_NAME_free(name);

    // 设置证书请求公钥
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa);
    X509_REQ_set_pubkey(req, pkey);

    // 签名证书请求
    X509_REQ_sign(req, pkey, EVP_sha512());
    EVP_PKEY_free(pkey);
    return true;
}

bool SSL_csr_Write(SSL *ssl, X509_REQ *req)
{
    // 导出为字符类型
    BIO *bio = BIO_new(BIO_s_mem());

    PEM_write_bio_X509_REQ(bio, req);


    char *csrData;
    long csrDataLen = BIO_get_mem_data(bio, &csrData);
    
    char *DataString = (char *) malloc(1 + sizeof(char) * csrDataLen);
    sprintf(DataString, "%.*s", int(csrDataLen), csrData);
    // 打印导出的证书请求数据
    printf("导出的证书请求数据:\n%s\n", DataString);
    //将证书发送给ssl对应的通讯方
    char crt_len[5] = {0};
    sprintf((char *)crt_len, "%04x", int(csrDataLen));
    SSL_WriteAll(ssl, crt_len, sizeof(crt_len) - 1);
    SSL_WriteAll(ssl, DataString, csrDataLen + 1);
    free(DataString);
    BIO_free(bio);
    bio = NULL;
    return true;
}

bool SSL_cert_Read(SSL *ssl, const char *Common_Name, const char *cert_pwd)
{   
    //从ssl通讯方读取证书
    char crt_len[5] = {0};
    SSL_ReadAll(ssl, crt_len, sizeof(crt_len) - 1);
    int dataLen = std::stoi((const char*)crt_len, 0, 16);
    char *dataStr = (char *)malloc(1 + sizeof(char) * dataLen);
    SSL_ReadAll(ssl, dataStr, dataLen + 1);
    dataStr[dataLen] = '\0';
    printf("证书字符串:%s\n", dataStr);
    BIO* bio_certString = BIO_new_mem_buf(dataStr, -1);
    
    // 从内存中读取 X.509 证书
    X509 *cert_new = PEM_read_bio_X509(bio_certString, NULL, NULL, NULL);
    // 释放 BIO 对象
    free(dataStr);
    BIO_free(bio_certString);
    cert_Save(cert_new, cert_pwd);
    // 清理证书对象
    X509_free(cert_new);
    printf("证书生成成功,程序退出\n");
    return true;
}