#ifndef VERIFIER_H
#define VERIFIER_H

#include <string>
#include <vector>
#include <openssl/ec.h>

/**
 * Verifier类实现DGTOTP协议中的验证者功能
 */
class Verifier {
public:
    // 当前验证周期
    static int current_verify_epoch;
    
    // 子树根
    static std::string SMT;
    
    // 变色龙哈希值
    static std::vector<int> CH_hash;
    
    // 变色龙哈希公钥
    static std::vector<EC_POINT*> CH_key;
    
    // 成员密文
    static std::vector<std::string> Member_cipher;
    
    // 群组公钥
    static std::string gpk;
    
    // Merkle证明
    static std::vector<std::string> merkle_proof;
    
    /**
     * 验证DGTOTP密码
     * @param password DGTOTP密码，包含验证点、随机数和密文
     * @param time 当前时间戳
     * @return 验证结果，1表示成功，0表示失败
     */
    static int Verify(const std::vector<std::string>& password, long time);
};

#endif // VERIFIER_H