#include <stdio.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <string.h>

// 将字符串转换为Base64编码
char* base64Encode(const unsigned char* input, int length) {
    BIO* bio = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new(BIO_s_mem());
    bio = BIO_push(bio, bmem);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input, length);
    BIO_flush(bio);

    char* base64Data;
    long base64Length = BIO_get_mem_data(bmem, &base64Data);

    char* base64String = (char*)malloc(base64Length + 1);
    if (base64String == NULL) {
        perror("内存分配失败");
        BIO_free_all(bio);
        return NULL;
    }

    memcpy(base64String, base64Data, base64Length);
    base64String[base64Length] = '\0';

    BIO_free_all(bio);
    return base64String;
}

//将base64转换为字符串
unsigned char* base64Decode(const char* input, int length, int* outputLength) {
    BIO* bio = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new_mem_buf(input, length);
    bio = BIO_push(bio, bmem);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    unsigned char* output = (unsigned char*)malloc(length);
    if (output == NULL) {
        perror("内存分配失败");
        BIO_free_all(bio);
        return NULL;
    }

    *outputLength = BIO_read(bio, output, length);
    BIO_free_all(bio);
    return output;
}

int main() {
    const unsigned char* originalString = (const unsigned char*)"Hello, World!";
    int originalLength = strlen((const char*)originalString);

    // 将字符串转换为Base64编码
    char* base64String = base64Encode(originalString, originalLength);
    if (base64String == NULL) {
        return 1;
    }

    printf("字符串转换为Base64编码: %s\n", base64String);

    // 将Base64编码的字符串转换为原始字符串
    int decodedLength = 0;
    unsigned char* decodedString = base64Decode(base64String, strlen(base64String), &decodedLength);
    if (decodedString == NULL) {
        free(base64String);
        return 1;
    }

    printf("Base64编码转换为字符串: %.*s\n", decodedLength, decodedString);

    // 清理资源
    free(base64String);
    free(decodedString);

    return 0;
}