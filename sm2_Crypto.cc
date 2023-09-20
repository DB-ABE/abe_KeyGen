#include <iostream>
#include <stdlib.h>
#include"sm2_Crypto.h"

const char* sm2_deckeyfile="cert//key_dec//deckey_1.pem";
const char* sm2_pubkeyfile="cert//key_enc//enckey_1.pem";
const char* sm2_signkeyfile="cert//key_sign//signkey_1.pem";
const char* sm2_verkeyfile="cert//key_ver//verkey_1.pem";
const char* pass="123456";

int sm2_test()
{
	return 0;
}

int sign_test()
{
	return 0;
}

int sm2_Encrypt(char* plaintext, unsigned char ciphertext[SM2_MAX_CIPHERTEXT_SIZE], size_t &len)
{
	SM2_KEY sm2key;
	sm2_key_generate(&sm2key);
	return 0;
}

int sm2_Decrypt(unsigned char *ciphertext, size_t len, unsigned char plaintext[SM2_MAX_PLAINTEXT_SIZE])
{

	return 0;
}

int sm2_Sign(char * plaintext, unsigned char sig[SM2_MAX_SIGNATURE_SIZE], size_t &siglen)
{

	return 1;
}

int sm2_Verify(char *plaintext, unsigned char sig[SM2_MAX_SIGNATURE_SIZE], size_t siglen)
{
	return 1;
}

// int main(){
// 	char *plain=(char*)"Hello World";
// 	unsigned char sig[SM2_MAX_SIGNATURE_SIZE];
// 	unsigned char ciphertext[SM2_MAX_CIPHERTEXT_SIZE];
// 	size_t len,siglen;
// 	unsigned char plaintext[SM2_MAX_PLAINTEXT_SIZE];
// 	sm2_Encrypt(plain, ciphertext, len);
// 	sm2_Decrypt(ciphertext, len, plaintext);
// 	printf("finally plain:%s\n", plaintext);
// 	sm2_Sign(plain, sig, siglen);
// 	sm2_Verify(plain, sig, siglen);
//   	// sm2();
//   	// sign();
// 	return 0;
// }