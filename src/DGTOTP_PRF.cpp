#include "DGTOTP_PRF.h"
#include "Parameter.h"
#include <cstring>
#include <openssl/rand.h>
#include <openssl/evp.h>

// 静态成员初始化
EVP_CIPHER_CTX* DGTOTP_PRF::cipher = nullptr;

unsigned char* DGTOTP_PRF::createKey() {
    // 初始化OpenSSL
    OpenSSL_add_all_algorithms();
    
    // 生成密钥
    unsigned char* key = (unsigned char*)malloc(16); // 128位AES密钥
    RAND_bytes(key, 16);
    
    return key;
}

unsigned char* DGTOTP_PRF::jdkAES(const std::string& context, unsigned char* originalKey) {
    // 初始化加密上下文
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, originalKey, nullptr);
    
    // 加密数据
    int outlen1, outlen2;
    unsigned char* outbuf = (unsigned char*)malloc(context.length() + EVP_MAX_BLOCK_LENGTH);
    
    EVP_EncryptUpdate(ctx, outbuf, &outlen1, (const unsigned char*)context.c_str(), context.length());
    EVP_EncryptFinal_ex(ctx, outbuf + outlen1, &outlen2);
    
    // 调整输出大小
    unsigned char* result = (unsigned char*)malloc(outlen1 + outlen2);
    memcpy(result, outbuf, outlen1 + outlen2);
    
    // 释放资源
    free(outbuf);
    EVP_CIPHER_CTX_free(ctx);
    
    return result;
}

unsigned char* DGTOTP_PRF::ksAES(const std::string& context, EVP_CIPHER_CTX* cipher) {
    // 加密数据
    int outlen1, outlen2;
    unsigned char* outbuf = (unsigned char*)malloc(context.length() + EVP_MAX_BLOCK_LENGTH);
    
    EVP_EncryptUpdate(cipher, outbuf, &outlen1, (const unsigned char*)context.c_str(), context.length());
    EVP_EncryptFinal_ex(cipher, outbuf + outlen1, &outlen2);
    
    // 调整输出大小
    unsigned char* result = (unsigned char*)malloc(outlen1 + outlen2);
    memcpy(result, outbuf, outlen1 + outlen2);
    
    // 释放资源
    free(outbuf);
    
    return result;
}

unsigned char* DGTOTP_PRF::keAES(const std::string& context, EVP_CIPHER_CTX* cipher) {
    return ksAES(context, cipher);
}

unsigned char* DGTOTP_PRF::kvAES(const std::string& context, EVP_CIPHER_CTX* cipher) {
    return ksAES(context, cipher);
}

unsigned char* DGTOTP_PRF::krAES(const std::string& context, EVP_CIPHER_CTX* cipher) {
    return ksAES(context, cipher);
}

unsigned char* DGTOTP_PRF::decrypt(unsigned char* result, size_t result_len, unsigned char* originalKey) {
    // 初始化解密上下文
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, originalKey, nullptr);
    
    // 解密数据
    int outlen1, outlen2;
    unsigned char* outbuf = (unsigned char*)malloc(result_len + EVP_MAX_BLOCK_LENGTH);
    
    EVP_DecryptUpdate(ctx, outbuf, &outlen1, result, result_len);
    EVP_DecryptFinal_ex(ctx, outbuf + outlen1, &outlen2);
    
    // 调整输出大小
    unsigned char* decrypted = (unsigned char*)malloc(outlen1 + outlen2);
    memcpy(decrypted, outbuf, outlen1 + outlen2);
    
    // 释放资源
    free(outbuf);
    EVP_CIPHER_CTX_free(ctx);
    
    return decrypted;
}