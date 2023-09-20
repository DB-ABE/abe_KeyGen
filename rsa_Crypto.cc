#include "rsa_Crypto.h"
using namespace std;
//初始化SHA
SHA_CTX SHA_init(string strData){
    SHA_CTX ctx;
    SHA1_Init(&ctx);
	SHA1_Update(&ctx, strData.c_str(), strlen(strData.c_str()));
    return ctx;
}
//加密
string RSA_Encrypt( const string strPemFileName, const string strData)
{
	if (strPemFileName.empty() || strData.empty())
	{
		assert(false);
		return "";
	}
	FILE* hPubKeyFile = fopen(strPemFileName.c_str(), "rb");
	if( hPubKeyFile == NULL )
	{
		assert(false);
		return ""; 
	}
	string strRet;
	RSA* pRSAPublicKey = RSA_new();
	if(PEM_read_RSA_PUBKEY(hPubKeyFile, &pRSAPublicKey, 0, 0) == NULL)
	{
		assert(false);
		return "";
	}
 
	int nLen = RSA_size(pRSAPublicKey);
	char* pEncode = new char[nLen + 1];
	int ret = RSA_public_encrypt(strData.length(), (const unsigned char*)strData.c_str(), (unsigned char*)pEncode, pRSAPublicKey, RSA_PKCS1_PADDING);
	if (ret >= 0)
	{
		strRet = string(pEncode, ret);
	}
	delete[] pEncode;
	RSA_free(pRSAPublicKey);
	fclose(hPubKeyFile);
	CRYPTO_cleanup_all_ex_data(); 
	return strRet;
}

//签名 use private key
string RSA_Sign( const string strPemFileName, string strData )
{
    if (strPemFileName.empty() || strData.empty())
    {
            assert(false);
            return "";
    }
    FILE* hPriKeyFile = fopen(strPemFileName.c_str(), "rb");
    if( hPriKeyFile == NULL )
    {
            assert(false);
            return "";
    }
    string strRet;
    RSA* pRSAPriKey = RSA_new();
    if(PEM_read_RSAPrivateKey(hPriKeyFile, &pRSAPriKey, 0, 0) == NULL)
    {
            assert(false);
            return "";
    }

    int nLen = RSA_size(pRSAPriKey);
    cout<<"RSAsize:"<<nLen<<endl;
    char* pEncode = new char[nLen + 1];
    unsigned int outlen;
    unsigned char digest[SHA_DIGEST_LENGTH];
 
	SHA_CTX ctx = SHA_init(strData);
    SHA1_Final(digest, &ctx);

    char mdString[SHA_DIGEST_LENGTH*2];
	for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
	sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);

    int ret = RSA_sign(NID_sha1, (unsigned char *)mdString, SHA_DIGEST_LENGTH*2 , (unsigned char*)pEncode, &outlen, pRSAPriKey);
    if (ret >= 0)
    {
        strRet = string(pEncode);
        cout << "singed successfully!"<< endl;
        //cout << "next \n" << pEncode << endl;
        cout << "critical length:" << outlen << endl;
    }
    if( ret != 1)
        cout << "sign failed\n";
    delete[] pEncode;
    RSA_free(pRSAPriKey);
    fclose(hPriKeyFile);
    CRYPTO_cleanup_all_ex_data();
    return strRet;
}
 
//解密
string RSA_Decrypt( const string strPemFileName, const string strData )
{
	if (strPemFileName.empty() || strData.empty())
	{
		assert(false);
		return "";
	}
	FILE* hPriKeyFile = fopen(strPemFileName.c_str(),"rb");
	if( hPriKeyFile == NULL )
	{
		assert(false);
		return "";
	}
	string strRet;
	RSA* pRSAPriKey = RSA_new();
	if(PEM_read_RSAPrivateKey(hPriKeyFile, &pRSAPriKey, 0, 0) == NULL)
	{
		assert(false);
		return "";
	}
	int nLen = RSA_size(pRSAPriKey);
	char* pDecode = new char[nLen+1];
 
	int ret = RSA_private_decrypt(strData.length(), (const unsigned char*)strData.c_str(), (unsigned char*)pDecode, pRSAPriKey, RSA_PKCS1_PADDING);
	if(ret >= 0)
	{
		strRet = string((char*)pDecode, ret);
	}
	delete [] pDecode;
	RSA_free(pRSAPriKey);
	fclose(hPriKeyFile);
	CRYPTO_cleanup_all_ex_data(); 
	return strRet;
}

//验证签名 use pubkey
int RSA_Verify( const string strPemFileName, const string strData , const string sign_data)
{
    if (strPemFileName.empty() || strData.empty())
    {
            assert(false);
            return 0;
    }
    FILE* hPubKeyFile = fopen(strPemFileName.c_str(), "rb");
    if( hPubKeyFile == NULL )
    {
            assert(false);
            return 0;
    }
    string strRet;
    RSA* pRSAPublicKey = RSA_new();
    if(PEM_read_RSA_PUBKEY(hPubKeyFile, &pRSAPublicKey, 0, 0) == NULL)
    {
            assert(false);
            return 0;
    }

    int nLen = RSA_size(pRSAPublicKey);
    char* pEncode = new char[nLen + 1];
    unsigned int outlen;
    unsigned char digest[SHA_DIGEST_LENGTH];
    
    SHA_CTX ctx = SHA_init(strData);
	SHA1_Final(digest, &ctx);
 
    char mdString[SHA_DIGEST_LENGTH*2];
	for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
	sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);


    int ret = RSA_verify(NID_sha1, (const unsigned char*)mdString, SHA_DIGEST_LENGTH*2,  (const unsigned char*)sign_data.c_str(), nLen,  pRSAPublicKey);
    if(ret != 1){
        cout << "verify error\n";
        unsigned long ulErr = ERR_get_error();
        char szErrMsg[1024] = {0};  
        cout << "error number:" << ulErr << endl; 
        char *pTmp = NULL;  
        pTmp = ERR_error_string(ulErr,szErrMsg); // 格式：error:errId:库:函数:原因  
        cout << szErrMsg << endl;
        return -1;
    }
    else
        cout << "verify success\n";
    delete[] pEncode;
    RSA_free(pRSAPublicKey);
    fclose(hPubKeyFile);
    CRYPTO_cleanup_all_ex_data();
    return 1;
}
