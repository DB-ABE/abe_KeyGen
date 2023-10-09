
#include <stdio.h>
#include <iostream>
#include <string>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <mysql/mysql.h>

#include "openssl/crypto.h"
#include "openssl/err.h"
#include "openssl/rsa.h"      
#include "cjson/cJSON.h"

#include "rsa_Crypto.h"
#include "abe_Crypto.h"
#include "SSL_socket.h"

#define CACERT "../tmp/cacert.pem"
#define CLIENT_CRT "../tmp/clientcert.pem"
#define CLIENT_KEY "../tmp/client.pem"
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(-2); }
#define SERVER_ADDR "127.0.0.1"
#define PORT 20001
#define abe_test_message "test"

#define SERVER_mode 1
#define CLIENT_mode 0
using namespace std;


const char *RSA_private_key = "../tmp/client.pem";

const char *RSA_public_key = "../tmp/clientcert.pem";
//测试abe密钥，需要保证../abe_key/abe_pp参数


int mysql_generateABEKey(string username, string attibute){
    unsigned char json_len_hex[5] = "0";
    int json_len;
	cJSON *request = cJSON_CreateObject();
    cJSON *response = cJSON_CreateObject();
    cJSON *key = NULL, *data = NULL;//用来提取json中的字段内容
    char *json_str = NULL, buf[1024];
    char* base64String = NULL;
    string uuid, sign_length, cipher, sign_data, sign_data_abe;
    uuid.assign("1");//记录uid，从数据库索引
    abe_user user;
    int sd=0, confd=0;
    unsigned int sign_len;
    SSL* ssl=NULL;
    SSL_CTX* ctx=NULL;
    struct sockaddr_in sa={0};
    X509* server_cert=NULL;
    char *str=NULL;
    ctx=InitSSL((char *)CACERT, (char *)CLIENT_CRT, (char *)CLIENT_KEY, CLIENT_mode);
    if(ctx==NULL) return -1;
    /* 指定加密器类型 */
    SSL_CTX_set_cipher_list (ctx, "ECDHE-RSA-AES256-SHA");
    SSL_CTX_set_mode (ctx, SSL_MODE_AUTO_RETRY);

    /*以下是正常的TCP socket建立过程 .............................. */
    printf("Begin tcp socket...\n");

    sd= socket (AF_INET, SOCK_STREAM, 0);       
    if(sd <= 0)
    {
        perror("socket");
        goto exit;
    }
    
    sa.sin_family      = AF_INET;
    sa.sin_addr.s_addr = inet_addr(SERVER_ADDR);   /* Server IP */
    sa.sin_port        = htons(PORT);          /* Server Port number */
    confd = connect(sd, (struct sockaddr*)&sa, sizeof(sa)); 
    if(confd < 0)
    {
        printf("connect error=%d\n",confd);
        goto exit;
    }


    /* TCP 链接已建立.开始 SSL 握手过程.......................... */
    printf("Begin SSL negotiation \n");

    /*申请一个SSL套接字*/
    ssl = SSL_new (ctx);                        
    if(ssl <= 0)
    {
        printf("Error creating SSL new \n");
        goto exit;
    }

    /*绑定读写套接字*/
    SSL_set_fd (ssl, sd);
    SSL_connect (ssl);               
    printf("链接已建立.开始 SSL 握手过程 \n");


    /*打印所有加密算法的信息(可选)*/
    printf ("SSL connection using %s\n", SSL_get_cipher (ssl));
    /*得到服务端的证书并打印些信息(可选) */
    SSL_get_peer_certificate(ssl);
    server_cert = SSL_get_peer_certificate (ssl);      
    printf ("Keymanager certificate:\n");

    str = X509_NAME_oneline (X509_get_subject_name (server_cert),0,0);
    printf ("/t subject: %s\n", str);
    free (str);

    str = X509_NAME_oneline (X509_get_issuer_name  (server_cert),0,0);
    printf ("/t issuer: %s\n", str);
    free (str);

    X509_free (server_cert);  /*如不再需要,需将证书释放 */

    /* 数据交换开始,用SSL_write,SSL_read代替write,read */
    printf("Begin SSL data exchange\n");

    {   

        //进行用户名和属性的签名
        auto ret = RSA_Sign(RSA_private_key, username+attibute, buf, sign_len);
        //cout<<"签名数据";
        // //以16进制记录签名数据
        // for(int i = 0; i < (int)sign_len; i++){
        //     char tmp[3];
        //     sprintf(tmp, "%02x", (unsigned char) buf[i]);
        //     sign_data.append(tmp);
        // }
        // cout<<sign_data<<endl;
        base64String = base64Encode((const unsigned char*)buf, sign_len);
        if (base64String == NULL) {
            cout<<"rsa签名base编码失败"<<endl;
            goto exit;
        }
        printf("rsa签名字符串转换为Base64编码: %s\n", base64String);
        sign_data.assign(base64String);
        //发送json
        cJSON_AddNumberToObject(request, "type", 0);
        cJSON_AddStringToObject(request, "uuid", uuid.c_str());
        cJSON_AddStringToObject(request, "userName", username.c_str());
        cJSON_AddStringToObject(request, "attribute", attibute.c_str());
        cJSON_AddStringToObject(request, "dbSignatureType", "RSA");
        cJSON_AddStringToObject(request, "dbSignature", base64String);
        json_str = cJSON_Print(request);
        cout<<"请求包长度:"<<strlen(json_str)<<endl;
        sprintf((char *)json_len_hex, "%04x", int(strlen(json_str)));
        cout<<json_len_hex<<endl;
        SSL_WriteAll (ssl, (char*)json_len_hex, sizeof(json_len_hex));
        SSL_WriteAll (ssl, json_str, strlen(json_str));
        free(json_str);
        free(base64String);
        base64String = NULL;

        //abe密钥测试,可删
        user.user_id = username;
        user.user_attr = attibute;
        
        SSL_ReadAll (ssl, (char*)json_len_hex, sizeof(json_len_hex)); 
        json_len = stoi((const char*)json_len_hex, 0, 16);
        cout<<"接收到响应包长度:"<<json_len<<endl;

        json_str = (char *)malloc(1 + sizeof(char) * json_len);
        SSL_ReadAll (ssl, json_str, json_len);
        json_str[json_len] = '\0';
        response = cJSON_Parse(json_str);
        free(json_str);
        //提取data字段值
        data = cJSON_GetObjectItem(response, "data");
        if (data == NULL || !cJSON_IsObject(data)) {
            printf("Failed to get 'data' field\n");
        }
        key = cJSON_GetObjectItem(data, "uuid");//提取uuid
        if (key != NULL && cJSON_IsString(key)) {
            if(strcmp(key->valuestring, uuid.c_str()) != 0){
                cout<<"两次uuid不匹配请联系密钥生成方"<<endl;
                goto exit;
            }
        }
        key = cJSON_GetObjectItem(response, "code");
        if(key->valueint != 0){
            cout<<"error code "<<key->valueint<<endl;
            key = cJSON_GetObjectItem(response, "msg");
            cout<<"get error message: ";
            cout<<key->valuestring<<endl;
            goto exit;
        }
        cout<<"code: "<<key->valueint<<endl;
        key = cJSON_GetObjectItem(response, "msg");
        cout<<key->valuestring<<endl;
        key = cJSON_GetObjectItem(data, "kmsSignatureType");
        if(strcmp(key->valuestring, "RSA") == 0){
            cout<<"获取abe密钥及RSA签名, 进行认证"<<endl;
            key = cJSON_GetObjectItem(data, "abe_key");//获取abe密钥
            string abe_cipher, abe_sign_data;

            // char tmpt[5];
            // for(int i = 0; i<int(strlen(key->valuestring))/2; i++){
            //     sprintf(tmpt, "0x%c%c", key->valuestring[i*2],key->valuestring[i*2+1]);
            //     abe_cipher += char(stoi(tmpt, 0, 16));
            // }
            
            base64String = (char *)base64Decode(key->valuestring, strlen(key->valuestring), &ret);
            if (base64String == NULL) {
                cout<<"abe_key_cipher base解码失败"<<endl;
                goto exit;
            }
            for(int i=0; i < ret; i++){
			    abe_cipher += base64String[i];
		    }
            free(base64String);
            base64String = NULL;
            key = cJSON_GetObjectItem(data, "kmsSignature");//获取abe签名

            // for(int i = 0; i<int(strlen(key->valuestring))/2; i++){
            //     sprintf(tmpt, "0x%c%c", key->valuestring[i*2],key->valuestring[i*2+1]);
            //     abe_sign_data += char(stoi(tmpt, 0, 16));
            // }

            base64String = (char *)base64Decode(key->valuestring, strlen(key->valuestring), &ret);
            if (base64String == NULL) {
                cout<<"abe_key_sign base解码失败"<<endl;
                goto exit;
            }
            for(int i=0; i < ret; i++){
			    abe_sign_data += base64String[i];
		    }
            ret = RSA_Verify(RSA_public_key, abe_cipher, abe_sign_data.c_str());
            if(ret!=1){
                cout<<"验签abe密钥失败, 请数据库传输正确的签名数据~~。"<<endl;
                goto exit;
            }
            cout<<"验证abe签名成功"<<endl;
            free(base64String);
            base64String = NULL;
            
            //abe测试，可删
            string abe_ct, abe_pt;
            user.user_key = RSA_Decrypt(RSA_private_key, abe_cipher);
            abe_Encrypt(abe_test_message, "attr1 and attr2", abe_ct);
            abe_Decrypt(abe_ct, user, abe_pt);
        }
    }

exit:
    /* 收尾工作 */
    SSL_shutdown (ssl);  /* send SSL/TLS close_notify */
    shutdown (sd,2);
    data = NULL;
    key = NULL;
    //将两个签名与abe密钥存入数据库，username, attibute, abe_key.c_str(), sign_data，sign_data_user; 
    if(request) cJSON_Delete(request);//同时会把key和data free掉
    if(response) cJSON_Delete(response);
    if(ctx) SSL_CTX_free(ctx);
    if(ssl) SSL_free (ssl);
    cout<<"程序退出"<<endl;
    return 1;
}

int main()
{
    //首先进行用户的检索，检查用户是否已经拥有密钥
    // MYSQL *conn=NULL;
    // MYSQL_RES *res=NULL;
    // MYSQL_ROW row;
    // int column;
    // const char *server = "10.12.153.17";
    // const char *user = "Database";
    // const char *password = "123456";
    // const char *database = "TPCC";
    // unsigned int port = 12348;
    // conn = mysql_init(NULL);
    // /* 连接数据库 */
    // if (!mysql_real_connect(conn, server, user, password, database, port, NULL, 0)) {
    //     cout << mysql_error(conn);
    //     goto exit;
    // }
    // cout<<"user: "<<user<<"成功连接至数据库"<<endl;
    // mysql_query(conn, "show databases");
    // res = mysql_store_result(conn);
    // column = mysql_num_fields(res);
    // while((row = mysql_fetch_row(res))){
    //     for(int i = 0; i<column; i++){
    //         cout<<row[i]<<"\t";
    //     }
    //     cout<<endl;
    // }
    
    mysql_generateABEKey("lisi", "|attr1|attr2|attr3 = 3|Date1 = March 20, 2022|Date2 = March 20, 2023|Date3 = March 20, 2022");
    
// exit:
//     if(conn)mysql_close(conn);
//     if(res)mysql_free_result(res);
    return 0;
}
