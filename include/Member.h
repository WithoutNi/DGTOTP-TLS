#ifndef MEMBER_H
#define MEMBER_H

#include <string>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <vector>

// 前向声明
class ChameleonHash;

/**
 * Member类 - 对应Java中的Member类
 * 实现群组成员功能
 */
class Member {
public:
    std::string ID_MENBER;          // 成员ID
    static unsigned char* alpha;     // ID的转换身份
    EVP_CIPHER_CTX* SECRET_KEY;     // 密钥kt
    static int k;                   // 安全参数
    static int N;                   // TOTP实例中的密码数量
    static int E;                   // TOTP协议实例数量
    static long START_TIME;         // 开始时间
    static long END_TIME;           // 结束时间
    static int Δs;                  // 密码生成周期
    static int Δe;                  // 验证周期
    std::string SECRET_SEED;        // 密钥种子sd
    std::string cipher_id;          // 身份密文
    unsigned char* cache_byte;      // 当前变量缓存16字节
    unsigned char cache_32[32];     // 当前变量缓存32字节
    std::string cache_string;       // 当前变量缓存字符串
    EVP_CIPHER_CTX* ks;            // 密钥ks
    EVP_CIPHER_CTX* ks_cipher;      // 密钥ks的加密上下文
    EVP_CIPHER_CTX* key_cipher;     // 密钥kt的加密上下文
    ChameleonHash* chame_hash;      // 变色龙哈希实例
    unsigned char* rand;            // 变色龙哈希碰撞

    /**
     * 构造函数
     */
    Member();
    
    /**
     * 析构函数
     */
    ~Member();

    /**
     * 成员初始化
     * @param ID 成员ID
     */
    void PInit(const std::string& ID);

    /**
     * 获取当前验证周期的密码种子
     * @param SECRET_KEY 密钥
     * @param time 时间
     * @return 密码种子
     */
    unsigned char* GetSD(EVP_CIPHER_CTX* SECRET_KEY, long time);

    /**
     * 生成密码
     * @param Ax 参数
     * @param time 时间
     * @return 密码数组
     */
    std::vector<std::string> PwGen(std::vector<unsigned char*>& Ax, long time);

    /**
     * 字节数组转十六进制字符串
     * @param b 字节数组
     * @param len 数组长度
     * @return 十六进制字符串
     */
    static std::string byte2hex(const unsigned char* b, size_t len);
};

#endif // MEMBER_H