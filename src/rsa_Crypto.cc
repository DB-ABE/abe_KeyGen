#include "rsa_Crypto.h"


// 加密
std::string RSA_Encrypt(const std::string strPemFileName, const std::string strData)
{
    // 检测输入是否合法
    if (strPemFileName.empty() || strData.empty())
    {
        //assert(false);
        return "";
    }
    // 打开rsa密钥文件
    FILE *hPubKeyFile = fopen(strPemFileName.c_str(), "rb");
    if (hPubKeyFile == NULL)
    {
        //assert(false);
        return "";
    }

    std::string strRet; // 存储加密结果
    // 从证书读取rsa密钥
    X509 *cert = PEM_read_X509(hPubKeyFile, nullptr, nullptr, nullptr);
    EVP_PKEY *evp_key = X509_get_pubkey(cert);
    RSA *pRSAPublicKey = EVP_PKEY_get1_RSA(evp_key);
    

    // 获取rsa长度
    int nLen = RSA_size(pRSAPublicKey);
    // 创建pencode临时存储加密密文
    char *pEncode = new char[nLen + 1];

    // 加密开始，分组进行加密
    if (strData.length() < RSA_Encrypt_length + 1)
    { // 如果长度小于一个分组
        int ret = RSA_public_encrypt(strData.length(), (const unsigned char *)strData.c_str(),
                                     (unsigned char *)pEncode, pRSAPublicKey, RSA_PKCS1_PADDING);
        if (ret >= 0)
        {
            strRet = std::string(pEncode, ret);
        }
        else
        {
            strRet = "";
        }
    }
    else
    { // 如果长度大于一个分组
        int flag = 1;
        for (int i = 0; i < (int)strData.length() / RSA_Encrypt_length; i++)
        {                                                                                  // 每次处理一个分组,循环读取RSA_Encrypt_length长度分组进行加密
            std::string Data = strData.substr(i * RSA_Encrypt_length, RSA_Encrypt_length); // 一个分组
            int ret = RSA_public_encrypt(Data.length(), (const unsigned char *)Data.c_str(),
                                         (unsigned char *)pEncode, pRSAPublicKey, RSA_PKCS1_PADDING);
            if (ret >= 0)
            {
                strRet += std::string(pEncode, ret);
            }
            else
            { // 加密失败，密文重置为""，跳出循环
                strRet = "";
                flag = 0;
                break;
            }
        }

        if (strData.length() % RSA_Encrypt_length != 0 && flag)
        { // 最后一段不够一个分组的情况, 前面的分组均正常
            std::string Data = strData.substr((strData.length() / RSA_Encrypt_length) * RSA_Encrypt_length,
                                              strData.length() % RSA_Encrypt_length); // 最后一段
            int ret = RSA_public_encrypt(Data.length(), (const unsigned char *)Data.c_str(),
                                         (unsigned char *)pEncode, pRSAPublicKey, RSA_PKCS1_PADDING);
            if (ret >= 0)
            {
                strRet += std::string(pEncode, ret);
            }
            else
            { // 加密失败, 密文重置为"";
                strRet = "";
            }
        }
    }
    // 释放资源
    delete[] pEncode;
    EVP_PKEY_free(evp_key);
    X509_free(cert);
    RSA_free(pRSAPublicKey);
    fclose(hPubKeyFile);
    CRYPTO_cleanup_all_ex_data();
    return strRet;
}

// 签名 use private key
int RSA_Sign(const std::string strPemFileName, std::string strData,
             unsigned char *pEncode, unsigned int &outlen)
{
    // 检查输入是否合法
    if (strPemFileName.empty() || strData.empty())
    {
        //assert(false);
        return -1;
    }
    // 读取rsa私钥文件，导入私钥
    FILE *hPriKeyFile = fopen(strPemFileName.c_str(), "rb");
    if (hPriKeyFile == NULL)
    {
        //assert(false);
        return -1;
    }
    RSA *pRSAPriKey = RSA_new();
    if (PEM_read_RSAPrivateKey(hPriKeyFile, &pRSAPriKey, 0, 0) == NULL)
    {
        //assert(false);
        return -1;
    }
    int flag = 1; // 记录签名的情况，1表示正常，0表示异常
    // 获取密钥长度
    int nLen = RSA_size(pRSAPriKey);
    std::cout << "RSAsize:" << nLen << std::endl;

    // 对签名信息hash，并将其转换为16进制字符串SHA_length * 2长度
    unsigned char digest[SHA_length];
    SHA512((unsigned char *)strData.c_str(), strData.length(), digest);

    // 进行签名
    int ret = RSA_sign(NID_SHA, (const unsigned char *)digest, SHA_length,
                       pEncode, &outlen, pRSAPriKey);
    if (ret >= 0)
    { // 签名成功
        std::cout << "singed successfully!" << std::endl;
        std::cout << "critical length:" << outlen << std::endl;
    }
    if (ret != 1)
    { // 签名失败
        std::cout << "sign failed\n";
        flag = 0;
    }
    // 释放资源
    RSA_free(pRSAPriKey);
    fclose(hPriKeyFile);
    CRYPTO_cleanup_all_ex_data();
    return flag;
}

// 解密
std::string RSA_Decrypt(const std::string strPemFileName, const std::string strData)
{
    // 检查输入是否合法
    if (strPemFileName.empty() || strData.empty())
    {
        //assert(false);
        return "";
    }
    // 导入rsa密钥文件并读取密钥
    FILE *hPriKeyFile = fopen(strPemFileName.c_str(), "rb");
    if (hPriKeyFile == NULL)
    {
        //assert(false);
        return "";
    }
    std::string strRet;
    RSA *pRSAPriKey = RSA_new();
    if (PEM_read_RSAPrivateKey(hPriKeyFile, &pRSAPriKey, 0, 0) == NULL)
    { // 密钥读取失败
        //assert(false);
        return "";
    }
    // 获取密钥长度
    int nLen = RSA_size(pRSAPriKey);
    char *pDecode = new char[nLen + 1];
    // 解密，不限长度，但为RSA_Decrypt_length的整数倍
    if (strData.length() < RSA_Decrypt_length + 1)
    { // 一个分组的情况
        int ret = RSA_private_decrypt(strData.length(), (const unsigned char *)strData.c_str(),
                                      (unsigned char *)pDecode, pRSAPriKey, RSA_PKCS1_PADDING);
        if (ret >= 0)
        { // 解密成功
            strRet = std::string((char *)pDecode, ret);
        }
        else
        { // 解密失败
            strRet = "";
        }
    }
    else
    { // 多个分组
        for (int i = 0; i < (int)strData.length() / (int)RSA_Decrypt_length; i++)
        {
            std::string Data = strData.substr(i * RSA_Decrypt_length, RSA_Decrypt_length);
            int ret = RSA_private_decrypt(Data.length(), (const unsigned char *)Data.c_str(),
                                          (unsigned char *)pDecode, pRSAPriKey, RSA_PKCS1_PADDING);
            if (ret >= 0)
            {
                strRet += std::string(pDecode, ret);
            }
            else
            { // 解密失败
                strRet = "";
                break;
            }
        }
    }

    delete[] pDecode;
    RSA_free(pRSAPriKey);
    fclose(hPriKeyFile);
    CRYPTO_cleanup_all_ex_data();
    return strRet;
}

// 验证签名 use pubkey
bool RSA_Verify(const std::string strPemFileName, const std::string strData,
                const unsigned char *sign_data)
{
    // 检验输入合法性
    if (strPemFileName.empty() || strData.empty())
    {
        //assert(false);
        return 0;
    }
    // 导入证书文件并读取公钥
    FILE *hPubKeyFile = fopen(strPemFileName.c_str(), "rb");
    if (hPubKeyFile == NULL)
    {
        //assert(false);
        return 0;
    }
    X509 *cert = PEM_read_X509(hPubKeyFile, nullptr, nullptr, nullptr);
    EVP_PKEY *evp_key = X509_get_pubkey(cert);
    RSA *pRSAPublicKey = EVP_PKEY_get1_RSA(evp_key);
    EVP_PKEY_free(evp_key);
    X509_free(cert);
    // 读取公钥长度
    int nLen = RSA_size(pRSAPublicKey);
    unsigned char digest[SHA_length];
    bool flag = true;
    // 对输入进行hash并转换16进制
    SHA512((const unsigned char *)strData.c_str(), strData.length(), digest);

    // 对签名进行认证
    int ret = RSA_verify(NID_SHA, (const unsigned char *)digest, SHA_length,
                         (const unsigned char *)sign_data, nLen, pRSAPublicKey);
    if (ret != 1)
    {
        std::cout << "verify error\n";
        unsigned long ulErr = ERR_get_error();
        char szErrMsg[1024] = {0};
        std::cout << "error number:" << ulErr << std::endl;
        ERR_error_string(ulErr, szErrMsg); // 格式：error:errId:库:函数:原因
        std::cout << szErrMsg << std::endl;
        flag = false;
    }
    else
        std::cout << "verify success\n";

    RSA_free(pRSAPublicKey);
    fclose(hPubKeyFile);
    CRYPTO_cleanup_all_ex_data();
    return flag;
}
