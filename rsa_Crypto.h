#include <iostream>
#include <string>
#include <cstring>
#include <cassert>

#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
using namespace std;

//初始化SHA
SHA_CTX SHA_init(string strData);
//加密
string RSA_Encrypt( const string strPemFileName, const string strData);
//签名 use private key
string RSA_Sign( const string strPemFileName, string strData);
//解密
string RSA_Decrypt( const string strPemFileName, const string strData);
//验证签名 use pubkey
int RSA_Verify( const string strPemFileName, const string strData , const string sign_data);

