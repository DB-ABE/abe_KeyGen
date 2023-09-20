#include <stdio.h>
#include<iostream>
#include <string.h>
#include <stdlib.h>
#include <gmssl/sm2.h>
#include <gmssl/mem.h>
#include <gmssl/error.h>
using namespace std;
const char* sm2_deckeyfile="cert//key_dec//deckey_1.pem";
const char* sm2_pubkeyfile="cert//key_enc//enckey_1.pem";
const char* sm2_signkeyfile="cert//key_sign//signkey_1.pem";
const char* sm2_verkeyfile="cert//key_ver//verkey_1.pem";
const char* pass="123456";
int sm2()
{
	SM2_KEY sm2_key;
	SM2_KEY pub_key;
	unsigned char plaintext[SM2_MAX_PLAINTEXT_SIZE];
	unsigned char ciphertext[SM2_MAX_CIPHERTEXT_SIZE];
	size_t len;
	sm2_key_generate(&sm2_key);
	// if (sm2_private_key_info_to_pem(&sm2_key, stdout) != 1) {
	// 	fprintf(stderr, "export failure\n");
	// }
	memcpy(&pub_key, &sm2_key, sizeof(SM2_POINT));
	format_bytes(stdout, 0, 0, "pub-key:x", pub_key.public_key.x, sizeof(pub_key.public_key.x));
	printf("key:%ld\n", sizeof(pub_key.public_key.x));
	format_bytes(stdout, 0, 0, "pub-key:y", pub_key.public_key.y, sizeof(pub_key.public_key.y));
	format_bytes(stdout, 0, 0, "private-key", sm2_key.private_key, sizeof(sm2_key.private_key));

	sm2_encrypt(&pub_key, (uint8_t *)"hello world!", strlen("hello world!"), ciphertext, &len);
	format_bytes(stdout, 0, 0, "ciphertext", ciphertext, len);
	printf("cipher-len:%ld\n", len);

	if (sm2_decrypt(&sm2_key, ciphertext, len, plaintext, &len) != 1) {
		fprintf(stderr, "error\n");
		return 1;
	}
	plaintext[len] = 0;
	printf("plaintext: %s\n", plaintext);

	return 0;
}

int sign()
{
	SM2_KEY sm2_key;
	SM2_KEY pub_key;
	unsigned char dgst[32];
	unsigned char sig[SM2_MAX_SIGNATURE_SIZE];
	size_t siglen;
	int ret;

	sm3_digest((unsigned char *)"hello world", strlen("hello world"), dgst);
	format_bytes(stdout, 0, 0, "to be signed digest", dgst, sizeof(dgst));

	sm2_key_generate(&sm2_key);

	sm2_sign(&sm2_key, dgst, sig, &siglen);
	format_bytes(stdout, 0, 0, "signature", sig, siglen);
  	cout<<siglen<<endl;
  
	memcpy(&pub_key, &sm2_key, sizeof(SM2_POINT));

	if ((ret = sm2_verify(&pub_key, dgst, sig, siglen)) != 1) {
		fprintf(stderr, "verify failed\n");
	} else {
		printf("verify success\n");
	}

	return 0;
}

int sm2_Encrypt(char* plaintext, unsigned char ciphertext[SM2_MAX_CIPHERTEXT_SIZE], size_t &len)
{
	FILE *keyfp = NULL;
	SM2_KEY pub_key;
	const char *keyfile=sm2_pubkeyfile;
	if (!(keyfp = fopen(keyfile, "rb"))) {
		fprintf(stderr, " open file '%s' failure\n", keyfile);
		return 0;
	}
	if (sm2_public_key_info_from_pem(&pub_key, keyfp) != 1) {
		fprintf(stderr, "load key failure\n");
		fclose(keyfp);
		return 0;
	}
	sm2_key_print(stdout, 0, 0, "SM2_encrypt_KEY", &pub_key);
//	gmssl_secure_clear(&pub_key, sizeof(pub_key));
	fclose(keyfp);


	format_bytes(stdout, 0, 0, "pub-key:x", pub_key.public_key.x, sizeof(pub_key.public_key.x));
	printf("key:%ld\n", sizeof(pub_key.public_key.x));
	format_bytes(stdout, 0, 0, "pub-key:y", pub_key.public_key.y, sizeof(pub_key.public_key.y));

	sm2_encrypt(&pub_key, (uint8_t *)plaintext, strlen(plaintext), ciphertext, &len);
	format_bytes(stdout, 0, 0, "ciphertext", ciphertext, len);

	return 0;
}

int sm2_Decrypt(unsigned char *ciphertext, size_t len, unsigned char plaintext[SM2_MAX_PLAINTEXT_SIZE])
{
	FILE *keyfp = NULL;
	SM2_KEY sm2_key;
	const char *keyfile=sm2_deckeyfile;
	if (!(keyfp = fopen(keyfile, "rb"))) {
		fprintf(stderr, " open file '%s' failure\n", keyfile);
		return 0;
	}
	if (sm2_private_key_info_decrypt_from_pem(&sm2_key, pass, keyfp) != 1) {
		fprintf(stderr, "load key failure\n");
		fclose(keyfp);
		return 0;
	}
	sm2_key_print(stdout, 0, 0, "SM2_KEY", &sm2_key);
//	gmssl_secure_clear(&sm2_key, sizeof(sm2_key));
	fclose(keyfp);

	if (sm2_decrypt(&sm2_key, ciphertext, len, plaintext, &len) != 1) {
		fprintf(stderr, "decryption error\n");
		return 1;
	}
	plaintext[len] = 0;
	printf("plaintext: %s\n", plaintext);

	return 0;
}

int sm2_Sign(char * plaintext, unsigned char sig[SM2_MAX_SIGNATURE_SIZE], size_t &siglen)
{

	FILE *keyfp = NULL;
	SM2_KEY sm2_key;
	const char *keyfile=sm2_signkeyfile;
	if (!(keyfp = fopen(keyfile, "rb"))) {
		fprintf(stderr, " open file '%s' failure\n", keyfile);
		return 0;
	}
	if (sm2_private_key_info_decrypt_from_pem(&sm2_key, pass, keyfp) != 1) {
		fprintf(stderr, "load key failure\n");
		fclose(keyfp);
		return 0;
	}
	sm2_key_print(stdout, 0, 0, "SM2_KEY", &sm2_key);
//	gmssl_secure_clear(&sm2_key, sizeof(sm2_key));
	fclose(keyfp);

	unsigned char dgst[32];

	sm3_digest((unsigned char *)plaintext, strlen(plaintext), dgst);
	format_bytes(stdout, 0, 0, "to be signed digest", dgst, sizeof(dgst));

	sm2_sign(&sm2_key, dgst, sig, &siglen);
	format_bytes(stdout, 0, 0, "signature", sig, siglen);
	printf("sign finshed!");
	return 1;
}

int sm2_Verify(char *plaintext, unsigned char sig[SM2_MAX_SIGNATURE_SIZE], size_t siglen)
{
	FILE *keyfp = NULL;
	SM2_KEY pub_key;
	const char *keyfile=sm2_verkeyfile;
	if (!(keyfp = fopen(keyfile, "rb"))) {
		fprintf(stderr, " open file '%s' failure\n", keyfile);
		return 0;
	}
	if (sm2_public_key_info_from_pem(&pub_key, keyfp) != 1) {
		fprintf(stderr, "load key failure\n");
		fclose(keyfp);
		return 0;
	}
	sm2_key_print(stdout, 0, 0, "SM2_verify_KEY", &pub_key);
//	gmssl_secure_clear(&pub_key, sizeof(pub_key));
	fclose(keyfp);

	unsigned char dgst[32];
	int ret;
	sm3_digest((unsigned char *)plaintext, strlen(plaintext), dgst);
	format_bytes(stdout, 0, 0, "verify signature:", sig, siglen);
  
	if ((ret = sm2_verify(&pub_key, dgst, sig, siglen)) != 1) {
		fprintf(stderr, "verify failed\n");
		return 0;
	} else {
		printf("verify success\n");
		return 1;
	}

	return 0;
}

int main(void){
	char *plain=(char*)"Hello World";
	unsigned char sig[SM2_MAX_SIGNATURE_SIZE];
	unsigned char ciphertext[SM2_MAX_CIPHERTEXT_SIZE];
	size_t len,siglen;
	unsigned char plaintext[SM2_MAX_PLAINTEXT_SIZE];
	sm2_Encrypt(plain, ciphertext, len);
	sm2_Decrypt(ciphertext, len, plaintext);
	printf("finally plain:%s\n", plaintext);
	sm2_Sign(plain, sig, siglen);
	sm2_Verify(plain, sig, siglen);
  	// sm2();
  	// sign();
}