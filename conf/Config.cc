#include <iostream>
#include "Config.h"
#include <fstream>

// 加载制定路径的配置文件
json loadConfiguration(std::string fileName) {
    std::ifstream configFile(fileName);
    if (!configFile.is_open()) {
        std::cerr << "Failed to open!" << fileName << std::endl;
        return nullptr;
    }
    json config;
    configFile >> config;
    return config;
}
 
// 根据给定的json数据，获取制定key的字符串型数值
std::string getConfigString(json js, std::string key) {
    if (js == NULL || key == "") {
        return "-1";
    }
    return js[key];
}
int getConfigInt(json js, std::string key) {
    if (js == NULL || key == "") {
        return -1;
    }
    return js[key];
}