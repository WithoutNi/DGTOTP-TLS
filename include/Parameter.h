#ifndef PARAMETER_H
#define PARAMETER_H

#include <string>
#include <vector>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/ec.h>

// 前向声明
class ChameleonHash;

/**
 * Parameter类 - 对应Java中的Parameter类
 * 用于存储和初始化DGTOTP系统的参数
 */
class Parameter {
public:
    static int U;                  // 群组成员数量
    static int k;                  // 安全参数
    static int N;                  // TOTP实例中的密码数量
    static int E;                  // TOTP协议实例数量
    static long START_TIME;        // 开始时间
    static long END_TIME;          // 结束时间
    static int Δe;                 // 验证周期
    static int Δs;                 // 密码生成周期
    static ChameleonHash* chame_hash; // 变色龙哈希实例
    static EVP_MD_CTX* digest;     // SHA256上下文
    static std::string G;          // 群组实例G
    static EVP_CIPHER_CTX* AesCipher; // AES加密上下文
    static unsigned char* nonce;   // AES-GCM nonce
    static std::vector<int> CH_hash; // V
    static std::vector<std::string> Member_cipher; // 成员身份密文
    static std::vector<EC_POINT*> CH_key; // 变色龙哈希公钥
    static std::vector<std::string> merkle_proof; // Merkle证明
    static int proof_len;          // 证明长度
    static std::string gpk;        // 群组公钥

    /**
     * 初始化参数
     */
    static void init();

    /**
     * SHA256哈希函数 - 字节数组版本
     * @param message 输入消息
     * @return 哈希结果
     */
    static unsigned char* Sha256(unsigned char* message, size_t length);

    /**
     * SHA256哈希函数 - 字符串版本
     * @param message 输入消息
     * @return 哈希结果
     */
    static unsigned char* Sha256(const std::string& message);

    /**
     * 字节数组转整数
     * @param bytes 字节数组
     * @return 整数值
     */
    static int bytesToInt(unsigned char* bytes);

    /**
     * 合并两个字节数组
     * @param byte_1 第一个字节数组
     * @param byte_1_len 第一个字节数组长度
     * @param byte_2 第二个字节数组
     * @param byte_2_len 第二个字节数组长度
     * @return 合并后的字节数组
     */
    static unsigned char* byteMerger(unsigned char* byte_1, size_t byte_1_len, 
                                    unsigned char* byte_2, size_t byte_2_len);

    /**
     * 整数转字节数组
     * @param i 整数值
     * @return 字节数组
     */
    static unsigned char* intToBytes(int i);
};

#endif // PARAMETER_H