#include <string.h>
#include <openabe/openabe.h>
#include <openabe/zsymcrypto.h>

using namespace oabe;
using namespace oabe::crypto;
using namespace std;

struct abe_user{
  string user_id;
  string user_key;
  string user_attr;
};


int abe_init();

int abe_KeyGen(abe_user &user);

int abe_Encrypt(string pt, string policy, string &ct);

int abe_Decrypt(string ct, abe_user user, string &pt);


int abe_Userkeyin(abe_user &user);