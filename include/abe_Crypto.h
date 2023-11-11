#include <string.h>
#include <openabe/openabe.h>
#include <openabe/zsymcrypto.h>


struct abe_user{
  std::string user_id;
  std::string user_key;
  std::string user_attr;
};

int abe_import_pp(oabe::OpenABECryptoContext &cpabe, const char *pp_path = "./abe_key/abe_pp");

int abe_import_msk(oabe::OpenABECryptoContext &cpabe, const char *sk_path = "./abe_key/abe_sk");

int abe_generate(oabe::OpenABECryptoContext &cpabe);

int abe_init(oabe::OpenABECryptoContext &cpabe);

void abe_KeyGen(oabe::OpenABECryptoContext &cpabe, abe_user &user);

void abe_KeyGen(abe_user &user, std::string abe_pp, std::string abe_msk);

void abe_Encrypt(oabe::OpenABECryptoContext &cpabe, std::string pt, std::string policy, std::string &ct);

void abe_Decrypt(oabe::OpenABECryptoContext &cpabe, std::string ct, abe_user user, std::string &pt);

//将参数和密钥导入到string类型中
bool parameter_import_string(std::string &public_parameter, std::string &secert_parameter, const char *pp_path = "./abe_key/abe_pp", const char *sk_path = "./abe_key/abe_sk");
