//#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "rsa_Crypto.h"


class rsa_Test : public testing::Test { // 继承了 testing::Test
protected:  
	static void SetUpTestSuite() {
		std::cout<<"Init rsa_Test..."<<std::endl;

	} 
	static void TearDownTestSuite() {
		std::cout<<"complete."<<std::endl;
	}
	virtual void SetUp() override {
	}
	virtual void TearDown() override {
	}
};


TEST_F(rsa_Test, Encrypt)
{
	const std::string test= "test";
    EXPECT_STREQ("", RSA_Encrypt("", "").c_str());
    EXPECT_STREQ("", RSA_Encrypt("nocert", "").c_str());
    EXPECT_STREQ("", RSA_Encrypt("nocert", test).c_str());
    std::string ct = RSA_Encrypt("./cert/KMS/KMS_cert.pem", test);
    EXPECT_NE("", ct);
    EXPECT_STREQ("", RSA_Decrypt("", "").c_str());
    EXPECT_STREQ("", RSA_Decrypt("noprikey", "").c_str());
    EXPECT_STREQ("", RSA_Decrypt("noprikey", ct).c_str());
    EXPECT_STREQ("", RSA_Decrypt("./tmp/DB_prikey.pem", ct).c_str());
    EXPECT_STREQ(test.c_str(), RSA_Decrypt("./prikey/KMS/KMS_prikey.pem", ct).c_str());
    ct = RSA_Encrypt("./cert/KMS/KMS_cert.pem", "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111");
    EXPECT_STREQ("11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111", RSA_Decrypt("./prikey/KMS/KMS_prikey.pem", ct).c_str());
}

TEST_F(rsa_Test, Sign)
{
    unsigned char pencode[256] = {0};
    unsigned int outlen = 0;
	const std::string test= "test";
    EXPECT_EQ(-1, RSA_Sign("", "", pencode, outlen));
    EXPECT_EQ(-1, RSA_Sign("noprikey", "", pencode, outlen));
    EXPECT_EQ(-1, RSA_Sign("noprikey", test, pencode, outlen));
    EXPECT_EQ(1, RSA_Sign("./prikey/KMS/KMS_prikey.pem", test, pencode, outlen));
    EXPECT_EQ(0, RSA_Verify("", "", pencode));
    EXPECT_EQ(0, RSA_Verify("nocert", "", pencode));
    EXPECT_TRUE(RSA_Verify("./cert/KMS/KMS_cert.pem", test, pencode));
    EXPECT_FALSE(RSA_Verify("./cert/DB/DB_cert.pem", test, pencode));
}
int main(int argc, char** argv){
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}