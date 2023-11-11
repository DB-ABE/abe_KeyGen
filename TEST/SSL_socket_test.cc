//#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "SSL_socket.h"
#include "Config.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

class SSL_Test : public testing::Test { // 继承了 testing::Test
protected:  
	static void SetUpTestSuite() {
		std::cout<<"Init SSL_Test..."<<std::endl;

	} 
	static void TearDownTestSuite() {
		std::cout<<"complete."<<std::endl;
	}
	virtual void SetUp() override {
	}
	virtual void TearDown() override {
	}
};
int sock_init(){
	int sd = socket (AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in sa={0};
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = inet_addr("127.0.0.1");   /* Server IP */
    sa.sin_port        = htons(20005);          /* Server Port number */
    int confd = connect(sd, (struct sockaddr*)&sa, sizeof(sa));
	puts("可以继续");
	return sd;
}

TEST_F(SSL_Test, base64)
{
	const char *base_string = "test";
	int base_length;
	char *base64String_encode = base64Encode((const unsigned char *)base_string, strlen(base_string));
	char *base64String_decode = (char *)base64Decode(base64String_encode, strlen(base64String_encode), &base_length);
	EXPECT_GT(base_length, 0);
	EXPECT_STREQ(base_string, base64String_decode);
	free(base64String_encode);
	free(base64String_decode);
}

TEST_F(SSL_Test, ssl){
	int EXPECT_ret = 0;
	json config = loadConfiguration("./conf/Config.json");
	std::string ca_cert = getConfigString(config, "CA_cert");
	std::string KMS_private_key = getConfigString(config, "KMS_prikey");
	std::string KMS_cert = getConfigString(config, "KMS_cert");
	std::string verify_key = getConfigString(config, "DB_cert");
	std::string user_cert_pwd = getConfigString(config, "user_cert_pwd");
	int PORT = getConfigInt(config, "PORT");
	SSL_CTX *ctx = cert_SSL_Init("", "", NULL, 0);
	if(ctx == NULL) EXPECT_ret = 1;
	EXPECT_EQ(0, EXPECT_ret);
	SSL_CTX_free(ctx);
	ctx = cert_SSL_Init("", "", NULL, 1);
	if(ctx == NULL) EXPECT_ret = 1;
	EXPECT_EQ(1, EXPECT_ret);
	ctx = cert_SSL_Init(KMS_cert.c_str(), "", NULL, 1);
	if(ctx == NULL) EXPECT_ret = 1;
	EXPECT_EQ(1, EXPECT_ret);
	ctx = cert_SSL_Init(KMS_cert.c_str(), KMS_private_key.c_str());
	if(ctx) EXPECT_ret = 0;
	EXPECT_EQ(0, EXPECT_ret);
	SSL_CTX_free(ctx);
	ctx = InitSSL((char *)ca_cert.c_str(), (char *)"",(char *)"", 1);
	if(ctx == NULL) EXPECT_ret = 1;
	EXPECT_EQ(1, EXPECT_ret);
	ctx = InitSSL((char *)ca_cert.c_str(), (char *)KMS_cert.c_str(), (char *)"", 0);
	if(ctx == NULL) EXPECT_ret = 1;
	EXPECT_EQ(1, EXPECT_ret);
	ctx = InitSSL((char *)ca_cert.c_str(), (char *)KMS_cert.c_str(), (char *)"/tmp/DB_prikey.pem", 0);
	if(ctx == NULL) EXPECT_ret = 1;
	EXPECT_EQ(1, EXPECT_ret);
	ctx = InitSSL((char *)ca_cert.c_str(), (char *)KMS_cert.c_str(), (char *)KMS_private_key.c_str(), 0);
	if(ctx) EXPECT_ret = 0;
	EXPECT_EQ(0, EXPECT_ret);
	EXPECT_FALSE(check_cert(""));
	EXPECT_TRUE(check_cert("./cert/CA/CA_cert.pem"));
	int sd = sock_init();
	SSL *ssl = SSL_new(ctx);
	SSL_set_fd (ssl, sd);
	SSL_connect(ssl); 
	show_SSL(ssl);
	
	std::string uuid, sign_type, user_sign, username, attibute, cipher;
	int request_code;
	SSL_Json_Get(ssl, uuid, username, attibute, sign_type, user_sign, request_code);
	SSL_Json_Get(ssl, uuid, username, attibute, sign_type, user_sign, request_code);
	SSL_Json_Write(ssl, (char *)"test");
	SSL_response_error(ssl, "1", "test", 1);
	SSL_response_ok(ssl, "1", "test", "test", (unsigned char *)"test", 4, 1);
	
	EVP_PKEY *key = SSL_PKEY_Read("");
	if(key == NULL) EXPECT_ret = 1;
	EXPECT_EQ(1, EXPECT_ret);
	key = SSL_PKEY_Read("./prikey/KMS/KMS_prikey.pem");
	if(key != NULL) EXPECT_ret = 0;
	EXPECT_EQ(0, EXPECT_ret);
	RSA *rsa = generate_prikey(65537, 2048, NULL);
	RSA_free(rsa);
	rsa = generate_prikey(65537, 2048, "test");
	X509_REQ *req = X509_REQ_new();
	// EXPECT_FALSE(info_csr_Set(req, NULL, "test", "test", "test"));
	// rsa = generate_prikey(65537, 2048, "test");
	EXPECT_TRUE(info_csr_Set(req, rsa, "test", "test", "test"));
	EXPECT_TRUE(SSL_csr_Write(ssl, req));
	BIO *bio = BIO_new(BIO_s_mem());
	PEM_write_bio_X509_REQ(bio, req);
	char *csrData;
    long csrDataLen = BIO_get_mem_data(bio, &csrData);
	char *DataString = (char *) malloc(1 + sizeof(char) * csrDataLen);
    sprintf(DataString, "%.*s", int(csrDataLen), csrData);
	BIO *bio_new = BIO_new(BIO_s_mem());
    BIO_puts(bio_new, DataString);
	X509 *cert = cert_from_str(bio_new, key);
	if(cert) EXPECT_ret = 1;
	EXPECT_EQ(1, EXPECT_ret);
	BIO_free(bio);
	X509_free(cert);
	cert = cert_Gen(req, NULL);
	if(cert == NULL) EXPECT_ret = 1;
	EXPECT_EQ(1, EXPECT_ret);
	cert = cert_Gen(req, key);
	if(cert) EXPECT_ret = 0;
	EXPECT_EQ(0, EXPECT_ret);
	cert_Save(cert, "./nofile");
	cert_Save(cert, "./tmp");
	SSL_cert_Write(ssl, cert);
	X509_free(cert);
	EVP_PKEY_free(key);
	SSL_Shut(ssl, bio_new, DataString, req, ctx);
}

int main(int argc, char** argv){
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}