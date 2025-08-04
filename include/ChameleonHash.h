#ifndef CHAMELEON_HASH_H
#define CHAMELEON_HASH_H

#include <string>
#include <openssl/ec.h>
#include <gmp.h>

/**
 * ChameleonHash类 - 对应Java中的ChameleonHash类
 * 实现变色龙哈希功能
 */
class ChameleonHash {
public:
    // 私钥sk
    mpz_t sk;
    
    // 基点G
    static EC_POINT* G;
    
    // 公钥pk
    EC_POINT* pk;
    
    // 有限域P
    static mpz_t p;
    
    // 阶N
    static mpz_t N;
    
    // 曲线
    static EC_GROUP* group;

    /**
     * 构造函数
     */
    ChameleonHash();
    
    /**
     * 析构函数
     */
    ~ChameleonHash();

    /**
     * 变色龙哈希初始化
     */
    static void init();

    /**
     * 设置密钥对
     * @param rk 随机密钥
     */
    void Setup(unsigned char* rk);

    /**
     * 获取随机数
     * @return 随机大整数
     */
    static void getRand(mpz_t result);

    /**
     * 计算哈希值 m1*P + r1*G
     * @param msg 消息
     * @param pk 公钥
     * @param rand 随机数
     * @return 哈希值
     */
    static int eval(unsigned char* msg, size_t msg_len, EC_POINT* pk, unsigned char* rand, size_t rand_len);

    /**
     * 验证哈希值
     * @param msg1 消息1
     * @param r1 随机数1
     * @param pk 公钥
     * @param CH2 哈希值2
     * @return 验证结果 (1成功，0失败)
     */
    static int Verify(unsigned char* msg1, size_t msg1_len, unsigned char* r1, size_t r1_len, 
                      EC_POINT* pk, int CH2);

    /**
     * 计算碰撞 r2 = sk*m1 + r1 - m2*sk mod N
     * @param msg1 消息1
     * @param r1 随机数1
     * @param msg2 消息2
     * @param sk 私钥
     * @return 碰撞值
     */
    static unsigned char* Collision(unsigned char* msg1, size_t msg1_len, 
                                   unsigned char* r1, size_t r1_len, 
                                   unsigned char* msg2, size_t msg2_len, 
                                   mpz_t sk);
};

#endif // CHAMELEON_HASH_H