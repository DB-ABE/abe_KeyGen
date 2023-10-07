#include "rsa_Crypto.h"
using namespace std;
//初始化SHA
SHA_CTX SHA_init(string strData){
    SHA_CTX ctx;
    SHA1_Init(&ctx);
	SHA1_Update(&ctx, strData.c_str(), strlen(strData.c_str()));
    cout<<"消息长度:"<<strlen(strData.c_str())<<endl;
    return ctx;
}
//加密
string RSA_Encrypt(const string strPemFileName, const string strData)
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
    // if(PEM_read_RSA_PUBKEY(hPubKeyFile, &pRSAPublicKey, 0, 0) == NULL)
    // {
    //         assert(false);
    //         return 0;
    // }
    X509 *cert = PEM_read_X509(hPubKeyFile, nullptr, nullptr, nullptr);
    pRSAPublicKey = EVP_PKEY_get1_RSA(X509_get_pubkey(cert));
	int nLen = RSA_size(pRSAPublicKey);
	char* pEncode = new char[nLen + 1];
    if(strData.length() < RSA_Encrypt_length+1){
        int ret = RSA_public_encrypt(strData.length(), (const unsigned char*)strData.c_str(), (unsigned char*)pEncode, pRSAPublicKey, RSA_PKCS1_PADDING);
        if (ret >= 0)
        {
            strRet = string(pEncode, ret);
        }
    }
    else{
        for(int i = 0; i<(int)strData.length()/RSA_Encrypt_length; i++){
            string Data=strData.substr(i*RSA_Encrypt_length, RSA_Encrypt_length);
            int ret = RSA_public_encrypt(Data.length(), (const unsigned char*)Data.c_str(), (unsigned char*)pEncode, pRSAPublicKey, RSA_PKCS1_PADDING);
            if (ret >= 0)
            {
                strRet += string(pEncode, ret);
            }
        }
        if(strData.length()%RSA_Encrypt_length!=0){
            string Data=strData.substr((strData.length()/RSA_Encrypt_length)*RSA_Encrypt_length, strData.length()%RSA_Encrypt_length);
        
            int ret = RSA_public_encrypt(Data.length(), (const unsigned char*)Data.c_str(), (unsigned char*)pEncode, pRSAPublicKey, RSA_PKCS1_PADDING);
            if (ret >= 0){
                strRet += string(pEncode, ret);
            }
        }
    }
	delete[] pEncode;
	RSA_free(pRSAPublicKey);
	fclose(hPubKeyFile);
	CRYPTO_cleanup_all_ex_data(); 
	return strRet;
}

//签名 use private key
int RSA_Sign( const string strPemFileName, string strData, char* pEncode, unsigned int &outlen)
{
    if (strPemFileName.empty() || strData.empty())
    {
            assert(false);
            return -1;
    }
    FILE* hPriKeyFile = fopen(strPemFileName.c_str(), "rb");
    if( hPriKeyFile == NULL )
    {
            assert(false);
            return -1;
    }
    RSA* pRSAPriKey = RSA_new();
    if(PEM_read_RSAPrivateKey(hPriKeyFile, &pRSAPriKey, 0, 0) == NULL)
    {
            assert(false);
            return -1;
    }

    int nLen = RSA_size(pRSAPriKey);
    cout<<"RSAsize:"<<nLen<<endl;
    unsigned char digest[SHA_length];
 
	// SHA_CTX ctx = SHA_init(strData);
    // SHA1_Final(digest, &ctx);
    SHA512((unsigned char *)strData.c_str(), strlen(strData.c_str()), digest);

    char mdString[SHA_length*2];
	for (int i = 0; i < SHA_length; i++)
	sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);

    int ret = RSA_sign(NID_SHA, (unsigned char *)mdString, SHA_length*2 , (unsigned char*)pEncode, &outlen, pRSAPriKey);
    if (ret >= 0)
    {   
        cout << "singed successfully!"<< endl;
        //cout << "next \n" << pEncode << endl;
        cout << "critical length:" << outlen << endl;
    }
    if( ret != 1)
        cout << "sign failed\n";

    
    RSA_free(pRSAPriKey);
    fclose(hPriKeyFile);
    CRYPTO_cleanup_all_ex_data();
    return 1;
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
    
    if(strData.length()<RSA_Decrypt_length+1){
        int ret = RSA_private_decrypt(strData.length(), (const unsigned char*)strData.c_str(), (unsigned char*)pDecode, pRSAPriKey, RSA_PKCS1_PADDING);
        if(ret >= 0)
        {
            strRet = string((char*)pDecode, ret);
        }
    }
    else{
        for(int i=0; i<(int)strData.length()/(int)RSA_Decrypt_length; i++){
            string Data=strData.substr(i*RSA_Decrypt_length, RSA_Decrypt_length);
            int ret = RSA_private_decrypt(Data.length(), (const unsigned char*)Data.c_str(), (unsigned char*)pDecode, pRSAPriKey, RSA_PKCS1_PADDING);
            if (ret >= 0)
            {
                strRet += string(pDecode, ret);
            }
        }
        if(strData.length()%RSA_Decrypt_length!=0){
            string Data=strData.substr((strData.length()/RSA_Decrypt_length)*RSA_Decrypt_length, strData.length()%strData.length());
            int ret = RSA_private_decrypt(Data.length(), (const unsigned char*)Data.c_str(), (unsigned char*)pDecode, pRSAPriKey, RSA_PKCS1_PADDING);
            if (ret >= 0){
                strRet += string(pDecode, ret);
            }
        }
    }

	delete [] pDecode;
	RSA_free(pRSAPriKey);
	fclose(hPriKeyFile);
	CRYPTO_cleanup_all_ex_data(); 
	return strRet;
}

//验证签名 use pubkey
int RSA_Verify( const string strPemFileName, const string strData , const char * sign_data)
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
    // if(PEM_read_RSA_PUBKEY(hPubKeyFile, &pRSAPublicKey, 0, 0) == NULL)
    // {
    //         assert(false);
    //         return 0;
    // }
    X509 *cert = PEM_read_X509(hPubKeyFile, nullptr, nullptr, nullptr);
    pRSAPublicKey = EVP_PKEY_get1_RSA(X509_get_pubkey(cert));
    int nLen = RSA_size(pRSAPublicKey);

    char* pEncode = new char[nLen + 1];
    unsigned char digest[SHA_length];
    
    // SHA_CTX ctx = SHA_init(strData);
	// SHA1_Final(digest, &ctx);
    SHA512((unsigned char *)strData.c_str(), strlen(strData.c_str()), digest);
    char mdString[SHA_length*2];
	for (int i = 0; i < SHA_length; i++)
	sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);


    int ret = RSA_verify(NID_SHA, (const unsigned char*)mdString, SHA_length*2,  (const unsigned char*)sign_data, nLen,  pRSAPublicKey);
    if(ret != 1){
        cout << "verify error\n";
        unsigned long ulErr = ERR_get_error();
        char szErrMsg[1024] = {0};  
        cout << "error number:" << ulErr << endl; 
        ERR_error_string(ulErr,szErrMsg); // 格式：error:errId:库:函数:原因  
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
