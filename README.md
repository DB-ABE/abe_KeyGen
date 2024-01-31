# 文档说明

TEST——单元测试代码

abe_key——属性基加密的主密钥

cert——证书存储目录

conf——配置文件

main——证书生成、密钥生成主函数

prikey——私钥文件

tmp——临时生成文件

test.info——测试输出文件

report——测试报告

# 使用示例

## 编译：

```
make clean
make
```

## 命令示例：

1. PKI证书生成(多线程,先开启server，然后开启一个或多个client)

```
./bin/cert_server
./bin/cert_client
```

2. abe密钥生成(多线程，先开启Keymanager,后开启一个或多个Database)

```
./bin/Keymanager
./bin/Database
```

# 测试

```
/* 需要gtest */
./TEST/bin/Config_test
./TEST/bin/rsa_Crypto_test
./TEST/bin/abe_Crypto_test

/* 测试SSL，先打开SSL_test_aux，然后打开SSL_socket_test */
./TEST/bin/SSL_test_aux
./TEST/bin/SSL_socket_test
```

# 生成测试报告

```
/*需要用到lcov工具*/
lcov -c -d /gcda -o test.info
genhtml -o report test.info --branch-coverage
```

