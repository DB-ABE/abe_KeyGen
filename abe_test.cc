#include <iostream>
#include <string>
#include <cassert>
#include <openabe/openabe.h>
#include <openabe/zsymcrypto.h>
#include <fstream>
using namespace std;
using namespace oabe;
using namespace oabe::crypto;

struct abe_user{
  string user_id;
  string user_key;
  string user_attr;
};
int abe_init(){
  InitializeOpenABE();
  string abe_pp, abe_sk;
  // string abe_gp;
  OpenABECryptoContext cpabe("CP-ABE");
  ofstream abe_securitykey("./abe_key/abe_sk", ios::out);
  if(!abe_securitykey){
    cout<<"error opening security key-file."<<endl;
    ShutdownOpenABE();
    return 0;
  }
  ofstream abe_publickey("./abe_key/abe_pp", ios::out);
  if(!abe_publickey){
    cout<<"error opening public key-file."<<endl;
    ShutdownOpenABE();
    return 0;
  }
  // ofstream abe_globalpameter("abe_gp", ios::out);
  // if(!abe_securitykey){
  //   cout<<"error opening global key-file."<<endl;
  //   ShutdownOpenABE();
  //   return 0;
  // }
  cpabe.generateParams();
  cpabe.exportPublicParams(abe_pp);
  cpabe.exportSecretParams(abe_sk);
  //cpabe.exportGlobalParams(abe_gp);
  abe_securitykey<<abe_sk;
  abe_publickey<<abe_pp;
  // abe_globalpameter<<abe_gp;
  cout<<"initial successfully!"<<endl;
  abe_securitykey.close();
  abe_publickey.close();
  // abe_globalpameter.close();
  ShutdownOpenABE();
  
  return 1;
}

int abe_KeyGen(abe_user &user){
  InitializeOpenABE();
  string abe_pp, abe_sk;
  // string abe_gp;
  OpenABECryptoContext cpabe("CP-ABE");
  ifstream abe_securitykey("./abe_key/abe_sk", ios::in);
  if(!abe_securitykey){
    cout<<"error opening security pameter-file."<<endl;
    ShutdownOpenABE();
    return 0;
  }
  ifstream abe_publickey("./abe_key/abe_pp", ios::in);
  if(!abe_publickey){
    cout<<"error opening public key-file."<<endl;
    ShutdownOpenABE();
    return 0;
  }
  // ifstream abe_globalpameter("abe_gp", ios::in);
  // if(!abe_globalpameter){
  //   cout<<"error opening global pameter-file."<<endl;
  //   ShutdownOpenABE();
  //   return 0;
  // }
  abe_securitykey>>abe_sk;
  abe_publickey>>abe_pp;
  // abe_globalpameter>>abe_gp;
  abe_securitykey.close();
  abe_publickey.close();
  // abe_globalpameter.close();

  cpabe.importPublicParams(abe_pp);
 
  cpabe.importSecretParams(abe_sk);
  //cpabe.importGlobalParams(abe_gp);
  cpabe.keygen(user.user_attr.c_str(), user.user_id.c_str());
  cpabe.exportUserKey(user.user_id.c_str(), user.user_key);
  // string policy="attr1 and attr2", pt="Hello world!", ct;
  // cpabe.encrypt(policy.c_str(), pt, ct);
  // cpabe.decrypt(user.user_id.c_str(), ct, pt);
  // cout << "Recovered message: " << pt << endl;
  ShutdownOpenABE();
  cout<<"generate key for "<<user.user_id<<endl;
  return 1;
}

int abe_Encrypt(string pt, string policy, string &ct){
  InitializeOpenABE();
  string abe_pp, abe_sk;
  OpenABECryptoContext cpabe("CP-ABE");
  ifstream abe_publickey("./abe_key/abe_pp", ios::in);
  if(!abe_publickey){
    cout<<"error opening public key-file."<<endl;
    ShutdownOpenABE();
    return 0;
  }
  abe_publickey>>abe_pp;
  abe_publickey.close();
  cpabe.importPublicParams(abe_pp);
  cpabe.encrypt(policy.c_str(), pt, ct);
  ShutdownOpenABE();
  cout<<"encrypt succefully!"<<endl;
  return 1;
}

int abe_Decrypt(string ct, abe_user user, string &pt){
  InitializeOpenABE();
  string abe_pp;
  OpenABECryptoContext cpabe("CP-ABE");
  ifstream abe_publickey("./abe_key/abe_pp", ios::in);
  if(!abe_publickey){
    cout<<"error opening public key-file."<<endl;
    ShutdownOpenABE();
    return 0;
  }
  abe_publickey>>abe_pp;
  abe_publickey.close();
  cpabe.importPublicParams(abe_pp);
  cpabe.importUserKey(user.user_id.c_str(), user.user_key);
  cpabe.decrypt(user.user_id.c_str(), ct, pt);
  cout << "Recovered message: " << pt << endl;
  ShutdownOpenABE();
  return 1;
}
int main(){
  string abe_pt1="Hello world!", abe_pt2, ct, policy="attr1 and attr2 and attr3<3 and Date > December 20, 2015";
  abe_user zhangsan;
  zhangsan.user_id="zhangsan";
  zhangsan.user_attr="|attr1|attr2|attr3 = 2|Date = March 10,2023";
  abe_init();
  abe_KeyGen(zhangsan);
  abe_Encrypt(abe_pt1, policy, ct);
  abe_Decrypt(ct, zhangsan, abe_pt2);
  return 0;
}