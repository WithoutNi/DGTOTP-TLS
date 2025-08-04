#include "Verifier.h"
#include "Parameter.h"
#include "ChameleonHash.h"
#include "MerkleTrees.h"
#include "TOTP.h"
#include "Member.h"
#include <cstring>
#include <ctime>

// 静态成员初始化
int Verifier::current_verify_epoch = 0;
std::string Verifier::SMT = "";
std::vector<int> Verifier::CH_hash;
std::vector<EC_POINT*> Verifier::CH_key;
std::vector<std::string> Verifier::Member_cipher;
std::string Verifier::gpk = "";
std::vector<std::string> Verifier::merkle_proof;

int Verifier::Verify(const std::vector<std::string>& password, long time) {
    // 获取当前验证周期
    current_verify_epoch = (int)((time - Parameter::START_TIME) / Parameter::Δe);
    
    // 计算密码序列号
    long pw_sequence = (time - current_verify_epoch * Parameter::Δe - Parameter::START_TIME) / Parameter::Δs;
    
    // 获取TOTP验证点(字节数组)
    unsigned char* cache_tem = TOTP::toBytes(password[0]);
    
    // 计算验证点
    for (int i = 0; i < pw_sequence + 1; i++) {
        unsigned char* temp = Parameter::Sha256(cache_tem, 32);
        memcpy(cache_tem, temp, 32);
        free(temp);
    }
    
    // TOTP验证点(字符串)
    std::string vp = Member::byte2hex(cache_tem, 32);
    
    // 获取置换MPI的Id索引
    int per_id_index = 0;
    for (int j = 0; j < Parameter::U; j++) {
        if (Member_cipher[j] == password[2]) {
            per_id_index = j;
            break;
        }
    }
    
    // 计算变色龙哈希值
    unsigned char* vp_bytes = Parameter::Sha256((vp + password[2] + std::to_string(current_verify_epoch)).c_str());
    int vp_point = ChameleonHash::eval(vp_bytes, 32, CH_key[per_id_index], 
                                     (unsigned char*)password[1].c_str(), password[1].length());
    
    // 验证变色龙哈希值
    if (vp_point != CH_hash[per_id_index]) {
        free(cache_tem);
        free(vp_bytes);
        return 0;
    }
    
    // 验证Merkle树和TOTP
    if (MerkleTrees::Verify(merkle_proof, SMT, gpk, current_verify_epoch) == 1 && 
        TOTP::Verify(vp, password[0], pw_sequence) == 1) {
        free(cache_tem);
        free(vp_bytes);
        return 1;
    }
    
    free(cache_tem);
    free(vp_bytes);
    return 0;
}