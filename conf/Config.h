#ifndef CONFIGURATION_H
#define CONFIGURATION_H
 
#include <iostream>
#include <string>
#include "json.hpp"
 
using json = nlohmann::json;
 
static std::string Host_Ip = "HOST_IP";
static std::string Port = "PORT";
 
// 加载制定路径的配置文件
json loadConfiguration(std::string fileName);
 
// 根据给定的json数据，获取制定key的字符串型或者整型数值
std::string getConfigString(json js, std::string key);
int getConfigInt(json js, std::string key);
#endif
