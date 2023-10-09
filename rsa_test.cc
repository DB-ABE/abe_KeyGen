#include "rsa_Crypto.h"
string RSA_private_key="./prikey.pem";
string RSA_public_key="./pubkey.pem";

int main(){
    string m = "test11";
	//hash SHA1
	auto sign_ = RSA_Sign(RSA_private_key, m);
	RSA_Verify(RSA_public_key, m,sign_);

    auto cipher= RSA_Encrypt(RSA_public_key, m);
    cout << "decrypt:" << RSA_Decrypt(RSA_private_key, cipher)<<endl; 
    
    return 1;
}