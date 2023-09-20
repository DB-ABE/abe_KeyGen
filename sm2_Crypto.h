#include <gmssl/sm2.h>
#include <gmssl/mem.h>
#include <gmssl/error.h>
#include <string.h>
using namespace std;



int sm2_test();

int sign_test();

int sm2_Encrypt(char* plaintext, unsigned char ciphertext[SM2_MAX_CIPHERTEXT_SIZE], size_t &len);

int sm2_Decrypt(unsigned char *ciphertext, size_t len, unsigned char plaintext[SM2_MAX_PLAINTEXT_SIZE]);

int sm2_Sign(char * plaintext, unsigned char sig[SM2_MAX_SIGNATURE_SIZE], size_t &siglen);

int sm2_Verify(char *plaintext, unsigned char sig[SM2_MAX_SIGNATURE_SIZE], size_t siglen);
