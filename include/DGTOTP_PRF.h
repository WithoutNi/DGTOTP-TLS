#ifndef DGTOTP_PRF_H
#define DGTOTP_PRF_H

#include <string>
#include <openssl/evp.h>

/**
 * DGTOTP_PRF类 - 对应Java中的DGTOTP_PRF类
 * 实现DGTOTP的伪随机函数
 */
class DGTOTP_PRF {
public:
    static EVP_CIPHER_CTX* cipher;

    /**
     * 创建密钥
     * @return 密钥
     */
    static unsigned char* createKey();

    /**
     * AES加密 - JDK版本
     * @param context 上下文
     * @param originalKey 原始密钥
     * @return 加密结果
     */
    static unsigned char* jdkAES(const std::string& context, unsigned char* originalKey);

    /**
     * AES加密 - ks版本
     * @param context 上下文
     * @param cipher 加密上下文
     * @return 加密结果
     */
    static unsigned char* ksAES(const std::string& context, EVP_CIPHER_CTX* cipher);

    /**
     * AES加密 - ke版本
     * @param context 上下文
     * @param cipher 加密上下文
     * @return 加密结果
     */
    static unsigned char* keAES(const std::string& context, EVP_CIPHER_CTX* cipher);

    /**
     * AES加密 - kv版本
     * @param context 上下文
     * @param cipher 加密上下文
     * @return 加密结果
     */
    static unsigned char* kvAES(const std::string& context, EVP_CIPHER_CTX* cipher);

    /**
     * AES加密 - kr版本
     * @param context 上下文
     * @param cipher 加密上下文
     * @return 加密结果
     */
    static unsigned char* krAES(const std::string& context, EVP_CIPHER_CTX* cipher);

    /**
     * AES解密
     * @param result 加密结果
     * @param originalKey 原始密钥
     * @return 解密结果
     */
    static unsigned char* decrypt(unsigned char* result, size_t result_len, unsigned char* originalKey);
};

#endif // DGTOTP_PRF_H