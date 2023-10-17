#include <fstream>
#include <cassert>
#include <iostream>
#include <unistd.h>
#include "abe_Crypto.h"
#include <mutex>
int abe_import_pp(oabe::OpenABECryptoContext &cpabe)
{
	std::string abe_pp;
	// 检测密钥文件是否存在
	std::ifstream abe_publickey("./abe_key/abe_pp", std::ios::in);
	if (!abe_publickey)
	{
		std::cout << "error opening public key-file." << std::endl;
		return -1;
	}

	// 导入密钥文件
	abe_publickey >> abe_pp;
	abe_publickey.close();
	// 导入密钥参数
	cpabe.importPublicParams((const std::string)abe_pp);
	return 1;
}

int abe_import_msk(oabe::OpenABECryptoContext &cpabe)
{
	std::string abe_sk;
	// 检测密钥文件是否存在
	std::ifstream abe_securitykey("./abe_key/abe_sk", std::ios::in);
	if (!abe_securitykey)
	{
		std::cout << "error opening security pameter-file." << std::endl;
		return -1;
	}

	// 导入密钥文件
	abe_securitykey >> abe_sk;
	abe_securitykey.close();
	// 导入密钥参数
	cpabe.importSecretParams((const std::string)abe_sk);
	return 1;
}

int abe_generate(oabe::OpenABECryptoContext &cpabe)
{
	std::string abe_pp, abe_sk;
	// 创建密钥和公共参数文件
	std::ofstream abe_securitykey("./abe_key/abe_sk", std::ios::out);
	if (!abe_securitykey)
	{
		std::cout << "error opening security key-file." << std::endl;
		return -1;
	}

	std::ofstream abe_publickey("./abe_key/abe_pp", std::ios::out);
	if (!abe_publickey)
	{
		std::cout << "error opening public key-file." << std::endl;
		return -1;
	}

	// 导入公共参数
	cpabe.generateParams();
	cpabe.exportPublicParams(abe_pp);
	cpabe.exportSecretParams(abe_sk);

	abe_securitykey << abe_sk;
	abe_publickey << abe_pp;
	std::cout << "abe_parameters generate successfully!" << std::endl;
	// 释放资源
	abe_securitykey.close();
	abe_publickey.close();
	return 1;
}

int abe_init(oabe::OpenABECryptoContext &cpabe)
{
	// 检测abe_key文件是否存在，若不存在，则创建
	if (access("./abe_key", F_OK) == 0)
		std::cout << "abe_key dir exists" << std::endl;
	else if (errno == ENOENT)
	{
		std::cout << "state:" << system("mkdir ./abe_key") << ",  successufully ";
		std::cout << "generate abe_key dir" << std::endl;
	}
	else
	{
		std::cout << "error happend for abe_key dir" << std::endl;
		return -1;
	}

	// 检测abe密钥是否已存在，若存在，则导入密钥，程序退出返回1
	if (access("./abe_key/abe_sk", F_OK) == 0)
	{
		std::cout << "abe_key exists, no need for generation~~!" << std::endl;
		int pp_flag = abe_import_pp(cpabe);
		int msk_flag = abe_import_msk(cpabe);
		if (pp_flag == 1 && msk_flag == 1)
			return 1;
		return -1;
	}
	else
		std::cout << "generate abe parameters" << std::endl;
	return abe_generate(cpabe);
}

void abe_KeyGen(oabe::OpenABECryptoContext &cpabe, abe_user &user)
{
	// 生成用户abe密钥
	cpabe.keygen((const std::string)user.user_attr, (const std::string)user.user_id);
	cpabe.exportUserKey((const std::string)user.user_id, user.user_key);

	std::cout << "generate key for " << user.user_id << std::endl;
}

void abe_KeyGen(abe_user &user, std::string abe_pp, std::string abe_msk)
{
	static std::mutex openabe_mutex;
	std::lock_guard<std::mutex> lock(openabe_mutex);
	oabe::InitializeOpenABE();
	oabe::OpenABECryptoContext cpabe("CP-ABE");
	cpabe.importSecretParams((const std::string)abe_msk);
	cpabe.importPublicParams((const std::string)abe_pp);
	abe_KeyGen(cpabe, user);
	oabe::ShutdownOpenABE();
}

int abe_Encrypt(oabe::OpenABECryptoContext &cpabe, std::string pt, std::string policy, std::string &ct)
{

	// 加密
	cpabe.encrypt(policy, (const std::string)pt, ct);
	std::cout << "encrypt succefully!" << std::endl;
	return 1;
}

int abe_Decrypt(oabe::OpenABECryptoContext &cpabe, std::string ct, abe_user user, std::string &pt)
{
	// 导入公共参数
	abe_import_pp(cpabe);
	// 导入用户密钥
	cpabe.importUserKey((const std::string)user.user_id, (const std::string)user.user_key);
	// 解密
	cpabe.decrypt((const std::string)user.user_id, (const std::string)ct, pt);
	std::cout << "Recovered message: " << pt << std::endl;
	return 1;
}

bool parameter_import_string(std::string &public_parameter, std::string &secert_parameter)
{
	std::ifstream abe_publickey("./abe_key/abe_pp", std::ios::in);
	if (!abe_publickey)
	{
		std::cout << "error opening public key-file." << std::endl;
		return false;
	}

	std::ifstream abe_secertkey("./abe_key/abe_sk", std::ios::in);
	if (!abe_secertkey)
	{
		std::cout << "error opening secert key-file." << std::endl;
		return false;
	}
	// 导入密钥文件
	abe_publickey >> public_parameter;
	abe_secertkey >> secert_parameter;
	abe_publickey.close();
	abe_secertkey.close();
	return true;
}
