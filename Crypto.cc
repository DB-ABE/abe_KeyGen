#include "abe_Crypto.h"
//#include"sm2_Crypto.h"
#include "rsa_Crypto.h"

// int test_sm2(){
//     char *plain=(char*)"Hello World";
// 	unsigned char sig[SM2_MAX_SIGNATURE_SIZE];
// 	unsigned char ciphertext[SM2_MAX_CIPHERTEXT_SIZE];
// 	size_t len,siglen;
// 	unsigned char plaintext[SM2_MAX_PLAINTEXT_SIZE];
// 	sm2_Encrypt(plain, ciphertext, len);
// 	sm2_Decrypt(ciphertext, len, plaintext);
// 	printf("finally plain:%s\n", plaintext);
// 	sm2_Sign(plain, sig, siglen);
// 	sm2_Verify(plain, sig, siglen);
//     return 1;
// }
string RSA_private_key="./prikey.pem";
string RSA_public_key="./pubkey.pem";

int test_abe(){
    string abe_pt1="Hello world!", abe_pt2, ct, policy="attr1 and attr2";
    abe_user zhangsan;
    zhangsan.user_id="zhangsan";
    zhangsan.user_attr="|attr1|attr2";
    abe_init();
    abe_KeyGen(zhangsan);
    abe_Encrypt(abe_pt1, policy, ct);
    abe_Decrypt(ct, zhangsan, abe_pt2);
    return 1;
}

void test_rsa(){
    string m = "test";
	//hash SHA1
	auto sign_ = RSA_Sign(RSA_private_key, m);
	RSA_Verify(RSA_public_key, m,sign_);

    auto cipher= RSA_Encrypt(RSA_public_key, m);
    cout << "decrypt:" << RSA_Decrypt(RSA_private_key, cipher)<<endl;

}

int main(){
    cout<<"RSA"<<endl;
    test_rsa();

    cout<<"ABE"<<endl;
    test_abe();
    return 0;
}