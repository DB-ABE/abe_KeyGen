#include "SSL_socket.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "Config.h"
#include "cjson/cJSON.h"
using namespace std;
void test(int sock){
    json config = loadConfiguration("./conf/Config.json");
	std::string ca_cert = getConfigString(config, "CA_cert");
	std::string KMS_private_key = getConfigString(config, "KMS_prikey");
	std::string KMS_cert = getConfigString(config, "KMS_cert");
    SSL_CTX *ctx = InitSSL((char *)ca_cert.c_str(), (char *)KMS_cert.c_str(), (char *)KMS_private_key.c_str(), 1);
    SSL *ssl = SSL_new (ctx);
    
	SSL_set_fd (ssl, sock);
	SSL_accept (ssl);     
    cJSON *request = cJSON_CreateObject();
    cJSON_AddNumberToObject(request, "type", 0);
    cJSON_AddStringToObject(request, "uuid", "1");
    cJSON_AddStringToObject(request, "userName", "test");
    cJSON_AddStringToObject(request, "attribute", "test");
    cJSON_AddStringToObject(request, "dbSignatureType", "RSA");
    cJSON_AddStringToObject(request, "dbSignature", ""); 
    char *json_str = cJSON_Print(request);
    char json_len_hex[5], test[5];
    sprintf((char *)json_len_hex, "%04x", int(strlen(json_str)));
    SSL_WriteAll(ssl, (char *)json_len_hex, sizeof(json_len_hex) - 1);
    SSL_WriteAll(ssl, json_str, strlen(json_str));
    free(json_str);
    cJSON_Delete(request);

    request = cJSON_CreateObject();
    cJSON_AddNumberToObject(request, "type", 0);
    cJSON_AddStringToObject(request, "uuid", "1");
    cJSON_AddStringToObject(request, "userName", "test");
    cJSON_AddStringToObject(request, "attribute", "test");
    cJSON_AddStringToObject(request, "dbSignatureType", "RSA");
    char *base64String = base64Encode((const unsigned char *)"test", 4);
    cJSON_AddStringToObject(request, "dbSignature", base64String); 
    json_str = cJSON_Print(request);
    sprintf((char *)json_len_hex, "%04x", int(strlen(json_str)));
    SSL_WriteAll(ssl, (char *)json_len_hex, sizeof(json_len_hex) - 1);
    SSL_WriteAll(ssl, json_str, strlen(json_str));
    free(json_str);
    free(base64String);
    cJSON_Delete(request);

    SSL_ReadAll(ssl, (char *)json_len_hex, sizeof(json_len_hex) - 1);
    SSL_ReadAll(ssl, test, strlen("test"));
    SSL_ReadAll(ssl, (char *)json_len_hex, sizeof(json_len_hex) - 1);
    int json_len = stoi((const char *)json_len_hex, 0, 16);
    json_str = (char *)malloc(1 + sizeof(char) * json_len);
    SSL_ReadAll(ssl, json_str, json_len);
    free(json_str);
    SSL_ReadAll(ssl, (char *)json_len_hex, sizeof(json_len_hex) - 1);
    json_len = stoi((const char *)json_len_hex, 0, 16);
    json_str = (char *)malloc(1 + sizeof(char) * json_len);
    SSL_ReadAll(ssl, json_str, json_len);
    free(json_str);

    json_len = stoi((const char *)json_len_hex, 0, 16);
    json_str = (char *)malloc(1 + sizeof(char) * json_len);
    SSL_ReadAll(ssl, json_str, json_len);
    free(json_str);

    json_len = stoi((const char *)json_len_hex, 0, 16);
    json_str = (char *)malloc(1 + sizeof(char) * json_len);
    SSL_ReadAll(ssl, json_str, json_len);
    free(json_str);
    
    FILE* file = fopen("./tmp/test_cert.pem", "r");
    X509* cert = PEM_read_X509(file, NULL, NULL, NULL);
    fclose(file);
    SSL_cert_Write(ssl, cert);
    X509_free(cert);
    SSL_Shut(ssl, NULL, NULL, NULL, ctx);
}

int main(){
	int listen_sock;
	int listen_max = 10;  // max listen number
	sockaddr_in sockaddr; // 定义IP地址结构
	int on = 1;
	listen_sock = socket(AF_INET, SOCK_STREAM, 0); // 初始化socket
	setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)); // 设置ip地址可重用
	sockaddr.sin_port = htons(20005);
	sockaddr.sin_family = AF_INET; // 设置结构类型为TCP/IP
	sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	bind(listen_sock, (struct sockaddr *)&sockaddr, sizeof(sockaddr));

	listen(listen_sock, listen_max); //     服务端开始监听

    while(1){
        sockaddr_in accept_sockaddr; // 定义accept IP地址结构
        socklen_t addrlen = sizeof(accept_sockaddr);
        memset(&accept_sockaddr, 0, addrlen);
        int accept_st = accept(listen_sock, (struct sockaddr *)&accept_sockaddr, &addrlen);
        test(accept_st);
    }
    return 0;
}