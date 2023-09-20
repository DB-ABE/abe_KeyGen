#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <string>
#include<string.h>
#include <unistd.h>
std::string sm2PriKeyStr="MIICSwIBADCB7AYHKoZIzj0CATCB4AIBATAsBgcqhkjOPQEBAiEA/v8AAAAA//8wRAQg/v8AAAAA//wEICjp+p6dn140TVqeS89lCafzl4n1FauPkt28vUFNlA6TBEEEMsSuLB8ZgRlfmQRGajnJlI/jC7/yZgvhcVpFiTNMdMe8Nzai9PZ3nFm9zuNraSFT0KmHfMYqR0AC3zLlITnwoAIhAP7///9yA99rIcYFK1O79Ak51UEjAgEBBIIBVTCCAVECAQEEINXHVaHjZdZjM3Ja9CyYR/VT4ZXqX2JCG1w59I+G2DoToIHjMIHgAgEBMCwGByqGSM49AQECIQD+/wAAAAD//zBEBCD+/wAAAAD//AQgKOn6np2fXjRNWp5Lz2UJp/OXifUVq4+S3by9QU2UDpMEQQQyxK4sHxmBGV+ZBEZqOcmUj+MLv/JmC+FxWkWJM0x0x7w3NqL09necWb3O42tpIVPQqYd8xipHQALfMuUhOfCgAiEA/v///3ID32shxgUrU7v0CTnVQSMCAQGhRANCAAQ8nhkap78DwzgwGnIBNfgXNIyoqPzfT+rnmXvRJ7NY8fjONiql9wQYxliyuAil6lNu2ax2MULoG43kdKE8a2JU";
std::string sm2PubKeyStr="MIIBMzCB7AYHKoZIzj0CATCB4AIBATAsBgcqhkjOPQEBAiEA/v8AAAAA//8wRAQg/v8AAAAA//wEICjp+p6dn140TVqeS89lCafzl4n1FauPkt28vUFNlA6TBEEEMsSuLB8ZgRlfmQRGajnJlI/jC7/yZgvhcVpFiTNMdMe8Nzai9PZ3nFm9zuNraSFT0KmHfMYqR0AC3zLlITnwoAIhAP7///9yA99rIcYFK1O79Ak51UEjAgEBA0IABDyeGRqnvwPDODAacgE1+Bc0jKio/N9P6ueZe9Ens1jx+M42KqX3BBjGWLK4CKXqU27ZrHYxQugbjeR0oTxrYlQ=";
 
 
int my_sm2encrpt(std::string keystr, unsigned char *sourStr, int cStrlen ,unsigned char *enStr)
{
    BIO* bp = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ectx = NULL;
    size_t cEnStrlen;
    char *cEnStr = NULL;
    char *chPublicKey = const_cast<char *>(keystr.c_str());
    if ((bp = BIO_new_mem_buf(chPublicKey, -1)) == NULL)
    {
        printf("BIO_new_mem_buf failed!\n");
        return NULL;
    }
    pkey = PEM_read_bio_PUBKEY(bp, NULL, NULL, NULL);
    BIO_free_all(bp);
    if ( (EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2)) != 1 )
    {
       goto clean_up;
    }
 
    if ( !(ectx = EVP_PKEY_CTX_new(pkey, NULL)) )
    {
       goto clean_up;
    }
 
    if ( (EVP_PKEY_encrypt_init(ectx)) != 1 )
    {
       goto clean_up;
    }
 
    if ( (EVP_PKEY_encrypt(ectx, NULL, &cEnStrlen,reinterpret_cast<unsigned char *>(sourStr), (size_t)(cStrlen))) != 1 )
    {
       goto clean_up;
    }
    if ( !(cEnStr = ( char *)malloc(cEnStrlen)) )
    {
       goto clean_up;
    }
 
    if ( (EVP_PKEY_encrypt(ectx,reinterpret_cast<unsigned char *>(cEnStr), &cEnStrlen,reinterpret_cast<unsigned char *>(sourStr), cStrlen)) != 1 )
    {
       goto clean_up;
    }
    printf("enStrLen2:\n %d\n",cEnStrlen);
    memcpy(enStr,cEnStr,cEnStrlen);
    return (int)(cEnStrlen);
 
 clean_up:
 
   if (pkey)
    {
        EVP_PKEY_free(pkey);
    }
    if (ectx)
    {
        EVP_PKEY_CTX_free(ectx);
    }
 
    if (sourStr)
    {
        free(sourStr);
    }
 
    if (cEnStr)
    {
        free(cEnStr);
    }
}
 
int dencryptStr(std::string keystr,unsigned char * cEnStr,int cEnstrlen,unsigned char* deStr)
 
{
    BIO* priBp = NULL;
    EVP_PKEY * mSm2PriKey;
    EVP_PKEY_CTX *ectx = NULL;
    size_t cDeStrlen=0;
    char *cDeStr = NULL;
    //create pri key
    char *chPrilicKey = const_cast<char *>(keystr.c_str());
    if ((priBp = BIO_new_mem_buf(chPrilicKey, -1)) == NULL)
    {
        printf("BIO_new_mem_buf failed!\n");
    }
    mSm2PriKey = PEM_read_bio_PrivateKey(priBp, NULL, NULL, NULL);
    BIO_free_all(priBp);
    if (NULL == mSm2PriKey)
    {
        ERR_load_crypto_strings();
        char errBuf[512];
        ERR_error_string_n(ERR_get_error(), errBuf, sizeof(errBuf));
        printf("load sm2 private key failed[%s]\n", errBuf);
    }
    //解密
    if ((EVP_PKEY_set_alias_type(mSm2PriKey, EVP_PKEY_SM2)) != 1 )
    {
         printf("EVP_PKEY_set_alias_type failed!\n");
    }
 
     if ( !(ectx = EVP_PKEY_CTX_new(mSm2PriKey, NULL)) )
     {
         printf("EVP_PKEY_CTX_new failed!\n");
     }
     if ( (EVP_PKEY_decrypt_init(ectx)) != 1 )
     {
         printf("EVP_PKEY_decrypt_init failed!\n");
     }
     if ( (EVP_PKEY_decrypt(ectx, NULL, &cDeStrlen,  reinterpret_cast<unsigned char *>(cEnStr), cEnstrlen)) != 1 )
     {
         printf("EVP_PKEY_decrypt failed!\n");
         ERR_load_crypto_strings();
         char errBuf[512];
         ERR_error_string_n(ERR_get_error(), errBuf, sizeof(errBuf));
         printf("EVP_PKEY_decrypt[%s]\n", errBuf);
     }
     if ( !(cDeStr = (char*)malloc(cDeStrlen)) )
     {
         printf(" (unsigned char *)malloc(cDeStrlen)) failed!\n");
     }
     if ( (EVP_PKEY_decrypt(ectx,  reinterpret_cast<unsigned char *>(cDeStr), &cDeStrlen, reinterpret_cast<unsigned char *>(cEnStr), cEnstrlen)) != 1 )
     {
         printf(" EVP_PKEY_decrypt failed!\n");
     }
     printf("cDeStrlen:%d\n",cDeStrlen);
     memcpy(deStr,cDeStr,cDeStrlen);
     EVP_PKEY_CTX_free(ectx);
     free(cDeStr);
     return cDeStrlen;
}
int main(int argc, char *argv[])
{
   unsigned char sm2_en[512],sm2_de[512];
     int sm2enStrLen,sm2deStrLen;
    for(int i = 64; i < sm2PriKeyStr.size(); i+=64)
    {
        if(sm2PriKeyStr[i] != '\n')
        {
            sm2PriKeyStr.insert(i, "\n");
        }
        ++i;
    }
    sm2PriKeyStr.insert(0, "-----BEGIN EC PARAMETERS-----\nBggqgRzPVQGCLQ==\n-----END EC PARAMETERS-----\n-----BEGIN EC PRIVATE KEY-----\n");
    sm2PriKeyStr.append("\n-----END EC PRIVATE KEY-----\n");
    for(int i = 64; i < sm2PubKeyStr.size(); i+=64)
    {
        if(sm2PubKeyStr[i] != '\n')
        {
            sm2PubKeyStr.insert(i, "\n");
        }
        ++i;
    }
    sm2PubKeyStr.insert(0, "-----BEGIN PUBLIC KEY-----\n");
    sm2PubKeyStr.append("\n-----END PUBLIC KEY-----\n");
    unsigned char source[20]={0x41,0x12,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10, 0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x20};
 
    sm2enStrLen=my_sm2encrpt(sm2PubKeyStr,source,20,sm2_en);
    printf("sm2enStrLen :%d \n",sm2enStrLen);
    printf("sm2_en: \n");
    for(int i=0;i<sm2enStrLen;i++)
    {
        printf("0x%02x ",sm2_en[i]);
    }
    printf("\n");
    sm2deStrLen=dencryptStr(sm2PriKeyStr,sm2_en,sm2enStrLen,sm2_de);
    printf("sm2deStrLen :%d \n",sm2deStrLen);
    printf("sm2_de: ");
    for(int i=0;i<sm2deStrLen;i++)
    {
        printf("0x%x ",sm2_de[i]);
    }
    printf("\n");
}
