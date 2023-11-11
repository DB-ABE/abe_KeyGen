//#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "Config.h"

class Config_Test : public testing::Test { // 继承了 testing::Test
protected:  
	static void SetUpTestSuite() {
		std::cout<<"Init Config_Test..."<<std::endl;

	} 
	static void TearDownTestSuite() {
		std::cout<<"complete."<<std::endl;
	}
	virtual void SetUp() override {
	}
	virtual void TearDown() override {
	}
};


TEST_F(Config_Test, load_get)
{
    json config = NULL;
    std::string test = getConfigString(config, "");
    EXPECT_STREQ("-1", test.c_str());
    int t = getConfigInt(config, "");
    EXPECT_EQ(-1, t);
    config = loadConfiguration("");
    EXPECT_EQ(nullptr, config);
    config = loadConfiguration("./conf/Config.json");
    EXPECT_NE(nullptr, config);
    test = getConfigString(config, "");
    EXPECT_STREQ("-1", test.c_str());
    test = getConfigString(config, "KMS_cert");
    EXPECT_STREQ("-1", test.c_str());
    t = getConfigInt(config, "");
    EXPECT_EQ(-1, t);
    t = getConfigInt(config, "PORT");
    EXPECT_NE(-1, t);
}