#ifndef RA_H
#define RA_H

#include <string>
#include <vector>
#include <openssl/evp.h>
#include <openssl/ec.h>

/**
 * RA类 - 对应Java中的RA类
 * 实现注册授权功能
 */
class RA {
public:
    static int U;                   // 群组成员数量
    static int k;                   // 安全参数
    static int N;                   // TOTP实例中的密码数量
    static int E;                   // TOTP协议实例数量
    static long START_TIME;         // 开始时间
    static long END_TIME;           // 结束时间
    static int Δe;                  // 验证周期
    static int Δs;                  // 密码生成周期
    static unsigned char* KEY_PERMUTATION; // 置换密钥
    static EVP_CIPHER_CTX* Key_RA;  // RA的密钥
    static std::vector<std::vector<std::string>> merkle_proof; // Merkle树根的证明
    static std::vector<std::vector<int>> CH_hash; // 变色龙哈希值
    static std::vector<std::vector<int>> ch_hash; // 置换后的变色龙哈希值
    static unsigned char* dvp;      // 虚拟验证点
    static unsigned char* rd;       // 随机数
    static std::vector<std::string> SMT; // 子Merkle树SMT
    static std::string gpk;         // 群组公钥
    static std::vector<std::vector<int>> per_table; // E置换集
    static std::vector<std::vector<std::string>> sub_tree; // Merkle树
    static unsigned char* rk;       // 变色龙哈希sk
    static std::vector<std::string> IDLG; // 存储已注册群组成员的身份
    static unsigned char* RL;       // 撤销列表
    static int verify_epoch;        // 特定验证周期
    static int per_id_index;        // 缓存置换后的id索引
    static int byte_size;           // 32字节
    static int alpha;               // 成员加入的索引
    static unsigned char* cache_tem; // 字节数据
    static std::vector<std::vector<unsigned char*>> ID_byte_cipher; // 成员ID密文
    static EVP_CIPHER_CTX* ks_cipher; // RA密钥密文
    static std::string G;          // 群组实例G
    static int current_verify_epoch; // 当前验证周期

    /**
     * RA设置
     * @param security_parameter 安全参数
     */
    static void RASetup(int security_parameter);

    /**
     * 整数转字节数组
     * @param i 整数
     * @return 字节数组
     */
    static unsigned char* intToBytes(int i);

    /**
     * 生成置换集
     * @param random 随机数生成器种子
     * @return 置换集
     */
    static std::vector<int> Permutation(unsigned int random_seed);

    /**
     * 更新群组管理消息
     * @param time 时间
     */
    void GMUpdate(long time);

    /**
     * 打开成员ID
     * @param password 密码
     * @param time 时间
     * @return 成员ID
     */
    static std::string Open(const std::vector<std::string>& password, long time);

    /**
     * AES加密
     * @param data 数据
     * @param data_len 数据长度
     * @param key 密钥
     * @param assocData 关联数据
     * @return 加密结果
     */
    static unsigned char* ASE_enc(unsigned char* data, size_t data_len, 
                                 unsigned char* key, unsigned char* assocData);

    /**
     * AES解密
     * @param key 密钥
     * @param data 数据
     * @param data_len 数据长度
     * @param assocData 关联数据
     * @return 解密结果
     */
    static unsigned char* ASE_dec(unsigned char* key, unsigned char* data, 
                                 size_t data_len, unsigned char* assocData);

    /**
     * 成员加入
     * @param ks 密钥
     * @param ID 成员ID
     * @param time 时间
     * @return 参数数组
     */
    std::vector<unsigned char*> Join(EVP_CIPHER_CTX* ks, const std::string& ID, long time);

    /**
     * 撤销成员
     * @param ID 成员ID
     * @param RA_key RA密钥
     * @return 撤销结果 (1成功，0失败)
     */
    static int Revoke(const std::string& ID, EVP_CIPHER_CTX* RA_key);
};

#endif // RA_H