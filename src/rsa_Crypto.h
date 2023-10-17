#include <iostream>
#include <string>
#include <cstring>
#include <cassert>

#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#define SHA_length SHA512_DIGEST_LENGTH
#define NID_SHA NID_sha512
#define RSA_Encrypt_length 245
#define RSA_Decrypt_length 256

// 初始化SHA，输入长度不限，输出为SHA_length长度
SHA_CTX SHA_init(std::string strData);
// 加密，输入长度不限
std::string RSA_Encrypt(const std::string strPemFileName, const std::string strData);
// 签名 use private key，输入长度不限
int RSA_Sign(const std::string strPemFileName, std::string strData, unsigned char *pEncode, unsigned int &outlen);
// 解密，输入长度不限
std::string RSA_Decrypt(const std::string strPemFileName, const std::string strData);
// 验证签名，输入为明文信息strData和签名信息sign_data，明文长度不限，签名长度为RSA签名长度（与密钥相关)
bool RSA_Verify(const std::string strPemFileName, const std::string strData, const unsigned char *sign_data);
