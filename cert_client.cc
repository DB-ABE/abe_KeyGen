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

#define SERVER_ADDR "127.0.0.1"
#define PORT 20000

int cert_generate(const char *country, const char *Organization, const char *Common_Name){
    int confd=0;
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
    printf("Begin SSL negotiation \n");
    OpenSSL_add_all_algorithms();
    
    OPENSSL_config(NULL);

    // 创建 RSA 密钥对
    RSA* rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    if (rsa == NULL) {
        perror("RSA 密钥对生成失败");
        return 1;
    }

    // 创建 X509_REQ 对象
    X509_REQ* req = X509_REQ_new();
    if (req == NULL) {
        perror("X509_REQ 对象创建失败");
        return 1;
    }
    // 设置证书请求版本
    X509_REQ_set_version(req, 0);

    // 设置证书请求持有者信息
    X509_NAME* name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)country, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)Organization, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)Common_Name, -1, -1, 0);
    X509_REQ_set_subject_name(req, name);

    // 设置证书请求公钥
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa);
    X509_REQ_set_pubkey(req, pkey);

    // 签名证书请求
    if (!X509_REQ_sign(req, pkey, EVP_sha512())) {
        perror("证书请求签名失败");
        X509_REQ_free(req);
        RSA_free(rsa);
        EVP_PKEY_free(pkey);
        return 1;
    }
    RSA_free(rsa);
    EVP_PKEY_free(pkey);

    // 导出为字符类型
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) {
        fprintf(stderr, "无法创建BIO对象\n");
        X509_REQ_free(req);
        return 1;
    }

    if (PEM_write_bio_X509_REQ(bio, req) == 0) {
        fprintf(stderr, "无法导出证书请求\n");
        BIO_free(bio);
        X509_REQ_free(req);
        return 1;
    }

    char *csrData;
    long csrDataLen = BIO_get_mem_data(bio, &csrData);
    if (csrDataLen <= 0) {
        fprintf(stderr, "无法获取导出的证书请求数据\n");
        BIO_free(bio);
        X509_REQ_free(req);
        return 1;
    }
    char *DataString = (char *) malloc(1 + sizeof(char) * csrDataLen);
    sprintf(DataString, "%.*s", csrDataLen, csrData);
    // 打印导出的证书请求数据
    printf("导出的证书请求数据:\n%s\n", DataString);
    //free(csrData);
    BIO_free(bio);
    //X509_REQ_free(req);
    puts("here");

    BIO *bio_req = BIO_new(BIO_s_mem());
    BIO_puts(bio_req, DataString);
    free(DataString);
    X509_REQ *req_new = PEM_read_bio_X509_REQ(bio_req, NULL, NULL, NULL);
    //BIO_free(bio_req);

    if (req_new == NULL) {
        fprintf(stderr, "无法解析证书请求\n");
        return 1;
        // 处理错误
    }

    // 加载 CA 的私钥
    FILE *caKeyFile = fopen("./tmp/ca.pem", "rb");
    if (!caKeyFile) {
        fprintf(stderr, "无法打开 CA 的私钥文件\n");
        X509_REQ_free(req_new);
        return 1;
    }
    EVP_PKEY *caKey = PEM_read_PrivateKey(caKeyFile, NULL, NULL, NULL);
    fclose(caKeyFile);
    
    if (!caKey) {
        fprintf(stderr, "无法读取 CA 的私钥\n");
        X509_REQ_free(req_new);
        return 1;
    }

    // 创建证书
    X509 *cert = X509_new();
    if (!cert) {
        fprintf(stderr, "无法创建证书对象\n");
        X509_REQ_free(req_new);
        EVP_PKEY_free(caKey);
        exit(EXIT_FAILURE);
    }

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
    X509_set_pubkey(cert, X509_REQ_get_pubkey(req_new));

    // 签名证书
    if (!X509_sign(cert, caKey, EVP_sha512())) {
        fprintf(stderr, "无法签名证书\n");
        X509_REQ_free(req_new);
        X509_free(cert);
        EVP_PKEY_free(caKey);
        return 1;
    }
    X509_REQ_free(req_new);
    EVP_PKEY_free(caKey);
    // 将证书保存到文件
    FILE *certFile = fopen("generated_certificate.crt", "wb");
    if (!certFile) {
        fprintf(stderr, "无法打开证书文件\n");
        X509_free(cert);
        return 1;
    }

    // 将证书转换为字符串
    BIO* bio_cert = BIO_new(BIO_s_mem());
    if (bio_cert == NULL) {
        perror("BIO 对象创建失败");
        X509_free(cert);
        return 1;
    }

    if (!PEM_write_bio_X509(bio_cert, cert)) {
        perror("证书转换为字符串失败");
        BIO_free(bio_cert);
        X509_free(cert);
        return 1;
    }
    X509_free(cert);
    char* certStr;
    long certSize = BIO_get_mem_data(bio_cert, &certStr);
    if (certSize <= 0) {
        perror("无效的证书字符串");
        BIO_free(bio_cert);
        return 1;
    }
    DataString = (char *)malloc(1 + sizeof(char) * certSize);
    sprintf(DataString, "%.*s", certSize, certStr);
    // 打印证书字符串
    printf("证书字符串：\n%s\n", DataString);

    free(DataString);
    // 清理资源
    BIO_free(bio_cert);

    return 0;
}
int main(){
    cert_generate("CN", "hust", "zhangsan");
    return 0;
}
//g++ -o cert_client -std=c++11 -pthread -Wall -g -O2 -DSSL_LIB_INIT  -I/usr/local/include -L/usr/local/lib cert_client.cc -lcrypto -lssl -lcjson -ldl -fsanitize=address