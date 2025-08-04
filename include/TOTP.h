#ifndef TOTP_H
#define TOTP_H

#include <string>
#include <openssl/sha.h>
#include <openssl/evp.h>

/**
 * TOTP类 - 对应Java中的TOTP类
 * 实现基于时间的一次性密码算法
 */
class TOTP {
public:
    static int k;                  // 安全参数
    static int N;                  // TOTP实例中的密码数量
    static long Δs;                // TOTP实例的开始时间
    static long Δe;                // TOTP实例的结束时间
    static std::string VERIFY_POINT; // 验证点
    static std::string SK_SEED;    // 密码种子
    static EVP_MD_CTX* digest;     // SHA256上下文
    static unsigned char sha256[32]; // SHA256哈希结果
    static unsigned char* cache_byte; // 缓存字节

    /**
     * 生成种子
     * @param key 密钥
     */
    static void getSeed(const std::string& key);

    /**
     * 设置密码数量
     * @param k 安全参数
     * @param START_TIME 开始时间
     * @param END_TIME 结束时间
     * @param PASS_GEN 密码生成周期
     */
    static void Setup(int k, long START_TIME, long END_TIME, long PASS_GEN);

    /**
     * TOTP初始化
     * @param SK_SEED 密码种子
     * @return 验证点
     */
    static std::string PInit(const std::string& SK_SEED);

    /**
     * 生成TOTP密码
     * @param SK_SEED 密码种子
     * @param pw_sequence 密码序列号
     * @return TOTP密码
     */
    static std::string PGen(const std::string& SK_SEED, long pw_sequence);

    /**
     * TOTP验证
     * @param VERIFY_POINT 验证点
     * @param password 密码
     * @param pw_sequence 密码序列号
     * @return 验证结果 (1成功，0失败)
     */
    static int Verify(const std::string& VERIFY_POINT, const std::string& password, long pw_sequence);

    /**
     * 字节数组转十六进制字符串
     * @param b 字节数组
     * @param len 数组长度
     * @return 十六进制字符串
     */
    static std::string byte2hex(const unsigned char* b, size_t len);

    /**
     * 十六进制字符串转字节数组
     * @param str 十六进制字符串
     * @return 字节数组
     */
    static unsigned char* toBytes(const std::string& str);

    /**
     * SHA256哈希函数 - 字节数组版本
     * @param tem 输入消息
     * @param len 消息长度
     * @return 哈希结果
     */
    static unsigned char* Hash_Sha256(const unsigned char* tem, size_t len);

    /**
     * SHA256哈希函数 - 字符串版本
     * @param message 输入消息
     * @return 哈希结果
     */
    static unsigned char* Hash_Sha256(const std::string& message);
};

#endif // TOTP_H