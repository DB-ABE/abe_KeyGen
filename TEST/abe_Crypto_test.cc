//#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "abe_Crypto.h"


class abe_Test : public testing::Test { // 继承了 testing::Test
protected:  
	static void SetUpTestSuite() {
		std::cout<<"Init abe_Test..."<<std::endl;

	} 
	static void TearDownTestSuite() {
		std::cout<<"complete."<<std::endl;
	}
	virtual void SetUp() override {
	}
	virtual void TearDown() override {
	}
};


TEST_F(abe_Test, abe_pkGen)
{
	oabe::InitializeOpenABE();
	oabe::OpenABECryptoContext cpabe("CP-ABE");
	system("rm -r abe_key");
	EXPECT_EQ(1, abe_init(cpabe));
	EXPECT_EQ(0, abe_init(cpabe));
	EXPECT_EQ(1, abe_generate(cpabe));
	oabe::ShutdownOpenABE();
}

TEST_F(abe_Test, abe_import)
{
	oabe::InitializeOpenABE();
	oabe::OpenABECryptoContext cpabe("CP-ABE");
	EXPECT_EQ(1, abe_import_pp(cpabe));
	EXPECT_EQ(-1, abe_import_pp(cpabe, ""));
	EXPECT_EQ(1, abe_import_msk(cpabe));
	EXPECT_EQ(-1, abe_import_msk(cpabe, ""));
	oabe::ShutdownOpenABE();
}

TEST_F(abe_Test, abe_keygen)
{
	oabe::InitializeOpenABE();
	abe_user user;
	user.user_attr = "|attr1";
	user.user_id = "zhangsan";
	std::string pp, msk;
	oabe::OpenABECryptoContext cpabe("CP-ABE");
	EXPECT_FALSE(parameter_import_string(pp, msk, "./abe_key/abe_pp", ""));
	EXPECT_FALSE(parameter_import_string(pp, msk, "", "./abe_key/abe_sk"));
	EXPECT_TRUE(parameter_import_string(pp, msk, "./abe_key/abe_pp", "./abe_key/abe_sk"));
	abe_import_msk(cpabe);
	abe_import_pp(cpabe);
	abe_KeyGen(cpabe, user);
	oabe::ShutdownOpenABE();
	abe_KeyGen(user, pp, msk);
}

TEST_F(abe_Test, abe_encrypt)
{
	oabe::InitializeOpenABE();
	std::string ct, pt;
	oabe::OpenABECryptoContext cpabe("CP-ABE");
	abe_user user;
	user.user_attr = "|attr1";
	user.user_id = "zhangsan";
	abe_import_msk(cpabe);
	abe_import_pp(cpabe);
	abe_KeyGen(cpabe, user);
	abe_Encrypt(cpabe, "test", "attr1", ct);
	abe_Decrypt(cpabe, ct, user, pt);
	oabe::ShutdownOpenABE();
}
int main(int argc, char** argv){
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}