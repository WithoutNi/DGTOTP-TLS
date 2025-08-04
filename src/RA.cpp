#include "RA.h"
#include "Parameter.h"
#include "ChameleonHash.h"
#include "DGTOTP_PRF.h"
#include "MerkleTrees.h"
#include "TOTP.h"
#include "Member.h"
#include <cstring>
#include <cmath>
#include <ctime>
#include <algorithm>
#include <random>
#include <openssl/rand.h>
#include <openssl/evp.h>

// 静态成员初始化
int RA::U = 0;
int RA::k = 0;
int RA::N = 0;
int RA::E = 0;
long RA::START_TIME = 0;
long RA::END_TIME = 0;
int RA::Δe = 0;
int RA::Δs = 0;
unsigned char* RA::KEY_PERMUTATION = nullptr;
EVP_CIPHER_CTX* RA::Key_RA = nullptr;
std::vector<std::vector<std::string>> RA::merkle_proof;
std::vector<std::vector<int>> RA::CH_hash;
std::vector<std::vector<int>> RA::ch_hash;
unsigned char* RA::dvp = nullptr;
unsigned char* RA::rd = nullptr;
std::vector<std::string> RA::SMT;
std::string RA::gpk = "";
std::vector<std::vector<int>> RA::per_table;
std::vector<std::vector<std::string>> RA::sub_tree;
unsigned char* RA::rk = nullptr;
std::vector<std::string> RA::IDLG;
unsigned char* RA::RL = nullptr;
int RA::verify_epoch = 0;
int RA::per_id_index = 0;
int RA::byte_size = 32;
int RA::alpha = 0;
unsigned char* RA::cache_tem = nullptr;
std::vector<std::vector<unsigned char*>> RA::ID_byte_cipher;
EVP_CIPHER_CTX* RA::ks_cipher = nullptr;
std::string RA::G = "";
int RA::current_verify_epoch = 0;

void RA::RASetup(int security_parameter) {
    k = security_parameter;
    
    // 变色龙哈希设置
    ChameleonHash::init();
    
    // 参数初始化
    Parameter::init();
    G = Parameter::G;
    START_TIME = Parameter::START_TIME;
    Δe = Parameter::Δe;
    END_TIME = Parameter::END_TIME;
    Δs = Parameter::Δs;
    N = Parameter::N;
    E = Parameter::E;
    U = Parameter::U;
    
    // 初始化数据结构
    SMT.resize(E);
    merkle_proof.resize(E);
    per_table.resize(E);
    sub_tree.resize((int)ceil(log2(U)), std::vector<std::string>(U));
    ID_byte_cipher.resize(U);
    
    rk = (unsigned char*)malloc(byte_size);
    dvp = (unsigned char*)malloc(byte_size);
    rd = (unsigned char*)malloc(byte_size);
    
    ch_hash.resize(E, std::vector<int>(U));
    CH_hash.resize(E, std::vector<int>(U));
    
    // 撤销列表
    RL = (unsigned char*)calloc(U, 1);
    
    // 已注册群组成员的身份列表
    IDLG.resize(U);
    
    // 生成RA的密钥
    unsigned char* key = DGTOTP_PRF::createKey();
    
    // RA_ASE密钥密文初始化
    ks_cipher = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ks_cipher);
    EVP_EncryptInit_ex(ks_cipher, EVP_aes_128_ecb(), nullptr, key, nullptr);
    
    // 初始化成员的ks
    unsigned char* Member_ks = nullptr;
    for (int j = 0; j < U; j++) {
        if (RL[j] == 1) continue; // 如果成员被撤销
        
        // 生成ks
        cache_tem = DGTOTP_PRF::ksAES(G + "KS" + std::to_string(j), ks_cipher);
        
        for (int i = 0; i < E; i++) {
            // 虚拟验证点
            unsigned char* part1 = DGTOTP_PRF::jdkAES(G + "DVP" + std::to_string(i), cache_tem);
            unsigned char* part2 = DGTOTP_PRF::jdkAES(G + "DVP" + std::to_string(i), cache_tem);
            memcpy(dvp, Parameter::byteMerger(part1, 16, part2, 16), byte_size);
            free(part1);
            free(part2);
            
            // 随机数
            part1 = DGTOTP_PRF::jdkAES(G + "DR" + std::to_string(i), cache_tem);
            part2 = DGTOTP_PRF::jdkAES(G + "DR" + std::to_string(i), cache_tem);
            memcpy(rd, Parameter::byteMerger(part1, 16, part2, 16), byte_size);
            free(part1);
            free(part2);
            
            // 生成变色龙哈希密钥
            part1 = DGTOTP_PRF::jdkAES(G + "CHR" + std::to_string(i), cache_tem);
            part2 = DGTOTP_PRF::jdkAES(G + "CHR" + std::to_string(i), cache_tem);
            memcpy(rk, Parameter::byteMerger(part1, 16, part2, 16), byte_size);
            free(part1);
            free(part2);
            
            // 设置变色龙哈希
            ChameleonHash ch;
            ch.Setup(rk);
            
            // 生成混洗的merkle子树节点
            CH_hash[i][j] = ChameleonHash::eval(dvp, byte_size, ch.pk, rd, byte_size);
        }
        
        free(cache_tem);
    }
    
    // 置换变色龙哈希值
    for (int i = 0; i < E; i++) {
        // 生成置换集
        cache_tem = DGTOTP_PRF::ksAES(G + "PM" + std::to_string(i), ks_cipher);
        unsigned int seed = 0;
        memcpy(&seed, cache_tem, sizeof(unsigned int));
        per_table[i] = Permutation(seed);
        free(cache_tem);
        
        // 置换变色龙哈希值
        for (int j = 0; j < U; j++) {
            ch_hash[i][per_table[i][j]] = CH_hash[i][j];
        }
        
        // 为变色龙哈希值生成E个Merkle树
        std::vector<std::string> ch_hash_str(U);
        for (int j = 0; j < U; j++) {
            ch_hash_str[j] = std::to_string(ch_hash[i][j]);
        }
        
        MerkleTrees merkle_tree(ch_hash_str);
        merkle_tree.merkle_tree();
        SMT[i] = merkle_tree.getRoot();
    }
    
    // 生成包含子树根的树的merkle证明
    std::vector<std::vector<std::string>> root_tree = MerkleTrees::get_tree(SMT);
    for (int i = 0; i < E; i++) {
        merkle_proof[i] = MerkleTrees::Get_Proof(root_tree, SMT[i], i);
    }
    
    // 群组公钥
    MerkleTrees merkle_tree(SMT);
    merkle_tree.merkle_tree();
    gpk = merkle_tree.getRoot();
    
    free(key);
}

unsigned char* RA::intToBytes(int i) {
    unsigned char* bytes = (unsigned char*)malloc(4);
    bytes[0] = (unsigned char)(i & 0xff);
    bytes[1] = (unsigned char)((i >> 8) & 0xff);
    bytes[2] = (unsigned char)((i >> 16) & 0xff);
    bytes[3] = (unsigned char)((i >> 24) & 0xff);
    return bytes;
}

std::vector<int> RA::Permutation(unsigned int random_seed) {
    std::vector<int> list(U);
    for (int i = 0; i < U; i++) {
        list[i] = i;
    }
    
    // 使用随机数生成器
    std::mt19937 rng(random_seed);
    std::shuffle(list.begin(), list.end(), rng);
    
    return list;
}

void RA::GMUpdate(long time) {
    int instance_index = (int)((time - START_TIME) / Δe);
    
    // V
    std::vector<int> V(U);
    std::vector<int> per_V(U);
    
    // 变色龙哈希公钥
    std::vector<EC_POINT*> public_key(U);
    std::vector<EC_POINT*> per_public_key(U);
    
    EVP_CIPHER_CTX* ks = nullptr;
    unsigned char* dvp = (unsigned char*)malloc(byte_size);
    unsigned char* rd = (unsigned char*)malloc(byte_size);
    unsigned char* rk = (unsigned char*)malloc(byte_size);
    unsigned char* ke = nullptr;
    unsigned char* re = (unsigned char*)malloc(16);
    
    std::vector<std::string> ciphertext(U);
    std::vector<std::string> per_ciphertext(U);
    
    // 计算U个成员身份密文
    for (int i = 0; i < U; i++) {
        cache_tem = DGTOTP_PRF::ksAES(G + "KS" + std::to_string(i), ks_cipher);
        
        // 虚拟vp
        unsigned char* part1 = DGTOTP_PRF::jdkAES(G + "DVP" + std::to_string(instance_index), cache_tem);
        unsigned char* part2 = DGTOTP_PRF::jdkAES(G + "DVP" + std::to_string(instance_index), cache_tem);
        memcpy(dvp, Parameter::byteMerger(part1, 16, part2, 16), byte_size);
        free(part1);
        free(part2);
        
        part1 = DGTOTP_PRF::jdkAES(G + "DR" + std::to_string(instance_index), cache_tem);
        part2 = DGTOTP_PRF::jdkAES(G + "DR" + std::to_string(instance_index), cache_tem);
        memcpy(rd, Parameter::byteMerger(part1, 16, part2, 16), byte_size);
        free(part1);
        free(part2);
        
        part1 = DGTOTP_PRF::jdkAES(G + "CHR" + std::to_string(instance_index), cache_tem);
        part2 = DGTOTP_PRF::jdkAES(G + "CHR" + std::to_string(instance_index), cache_tem);
        memcpy(rk, Parameter::byteMerger(part1, 16, part2, 16), byte_size);
        free(part1);
        free(part2);
        
        // 变色龙哈希设置
        ChameleonHash ch;
        ch.Setup(rk);
        public_key[i] = ch.pk;
        
        // 变色龙哈希eval
        V[i] = ChameleonHash::eval(dvp, byte_size, ch.pk, rd, byte_size);
        
        // 计算ID密文
        ke = DGTOTP_PRF::jdkAES("KeyGen" + std::to_string(instance_index), cache_tem);
        re = DGTOTP_PRF::jdkAES("Rand" + std::to_string(instance_index), cache_tem);
        
        // ASEe
        unsigned char* id_bytes = intToBytes(i);
        unsigned char* cipher = ASE_enc(id_bytes, 4, ke, re);
        ciphertext[i] = std::string(reinterpret_cast<char*>(cipher), 16);
        
        free(id_bytes);
        free(cipher);
        free(cache_tem);
    }
    
    // 置换
    cache_tem = DGTOTP_PRF::ksAES(G + "PM" + std::to_string(instance_index), ks_cipher);
    unsigned int seed = 0;
    memcpy(&seed, cache_tem, sizeof(unsigned int));
    per_table[instance_index] = Permutation(seed);
    free(cache_tem);
    
    for (int i = 0; i < U; i++) {
        per_V[i] = V[per_table[instance_index][i]];
        per_ciphertext[i] = ciphertext[per_table[instance_index][i]];
        per_public_key[i] = public_key[per_table[instance_index][i]];
    }
    
    // 发布群组管理消息
    std::vector<std::string> proof = merkle_proof[instance_index];
    
    // 证明长度
    Parameter::proof_len = proof.size();
    
    // 子树根证明
    Parameter::merkle_proof = proof;
    
    // 子树节点
    Parameter::CH_hash = per_V;
    
    // ID密文
    Parameter::Member_cipher = per_ciphertext;
    
    // 变色龙哈希公钥
    Parameter::CH_key = per_public_key;
    
    // gpk密钥
    Parameter::gpk = gpk;
    
    MerkleTrees::Verify(Parameter::merkle_proof, SMT[instance_index], SMT[instance_index], instance_index);
    
    // 释放资源
    free(dvp);
    free(rd);
    free(rk);
    if(ke) free(ke);
    if(re) free(re);
    
    for (int i = 0; i < U; i++) {
        if (public_key[i] != nullptr) {
            EC_POINT_free(public_key[i]);
        }
        if (per_public_key[i] != nullptr && per_public_key[i] != public_key[i]) {
            EC_POINT_free(per_public_key[i]);
        }
    }
}

std::string RA::Open(const std::vector<std::string>& password, long time) {
    // 获取置换MPI的Id索引
    per_id_index = 0;
    for (int j = 0; j < U; j++) {
        if (Parameter::Member_cipher[j] == password[2]) {
            per_id_index = j;
            break;
        }
    }
    
    verify_epoch = (int)((time - START_TIME) / Δe);
    current_verify_epoch = (int)((std::time(nullptr) * 1000 - Parameter::START_TIME) / Parameter::Δe);
    
    if (verify_epoch != current_verify_epoch) {
        return "";
    }
    
    long pw_sequence = (time - verify_epoch * Δe - START_TIME) / Δs;
    
    // 获取TOTP验证点(字节数组)
    unsigned char* cache_tem = TOTP::toBytes(password[0]);
    
    for (int i = 0; i < pw_sequence + 1; i++) {
        unsigned char* temp = Parameter::Sha256(cache_tem, 32);
        memcpy(cache_tem, temp, 32);
        free(temp);
    }
    
    // TOTP验证点(字符串)
    std::string vp = Member::byte2hex(cache_tem, 32);
    
    unsigned char* vp_bytes = Parameter::Sha256(vp + password[2] + std::to_string(verify_epoch));
    
    // "ISO-8859-1"字符串 -> 字节数组变色龙哈希eval
    int vp_point = ChameleonHash::eval(vp_bytes, 32, 
                                      Parameter::CH_key[per_table[verify_epoch][per_id_index]], 
                                      (unsigned char*)password[1].c_str(), password[1].length());
    
    // 置换
    cache_tem = DGTOTP_PRF::ksAES(G + "PM" + std::to_string(verify_epoch), ks_cipher);
    unsigned int seed = 0;
    memcpy(&seed, cache_tem, sizeof(unsigned int));
    std::vector<int> regen_per_table = Permutation(seed);
    free(cache_tem);
    
    // TOTP.verify && Merkle.verify
    if (MerkleTrees::Verify(Parameter::merkle_proof, SMT[verify_epoch], Parameter::gpk, verify_epoch) == 1 && 
        TOTP::Verify(vp, password[0], pw_sequence) == 1) {
        
        int ID_plain = 0;
        cache_tem = DGTOTP_PRF::ksAES(G + "KS" + std::to_string(per_table[verify_epoch][per_id_index]), ks_cipher);
        
        unsigned char* ke_bytes = DGTOTP_PRF::jdkAES("KeyGen" + std::to_string(verify_epoch), cache_tem);
        
        // 解密身份密文
        unsigned char* id_bytes = ASE_dec(ke_bytes, 
                                         (unsigned char*)Parameter::Member_cipher[per_id_index].c_str(), 
                                         Parameter::Member_cipher[per_id_index].length(), 
                                         DGTOTP_PRF::jdkAES("Rand" + std::to_string(verify_epoch), cache_tem));
        
        ID_plain = Parameter::bytesToInt(id_bytes);
        
        free(cache_tem);
        free(ke_bytes);
        free(id_bytes);
        
        return IDLG[ID_plain];
    }
    
    free(cache_tem);
    free(vp_bytes);
    
    return "";
}

unsigned char* RA::ASE_enc(unsigned char* data, size_t data_len, 
                          unsigned char* key, unsigned char* assocData) {
    // 初始化加密上下文
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    
    // 设置GCM模式
    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, key, Parameter::nonce);
    
    // 设置关联数据
    EVP_EncryptUpdate(ctx, nullptr, nullptr, assocData, 16);
    
    // 加密数据
    int outlen1, outlen2;
    unsigned char* outbuf = (unsigned char*)malloc(data_len + EVP_MAX_BLOCK_LENGTH);
    
    EVP_EncryptUpdate(ctx, outbuf, &outlen1, data, data_len);
    EVP_EncryptFinal_ex(ctx, outbuf + outlen1, &outlen2);
    
    // 获取认证标签
    unsigned char tag[16];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    
    // 组合密文和标签
    unsigned char* result = (unsigned char*)malloc(outlen1 + outlen2 + 16);
    memcpy(result, outbuf, outlen1 + outlen2);
    memcpy(result + outlen1 + outlen2, tag, 16);
    
    // 释放资源
    free(outbuf);
    EVP_CIPHER_CTX_free(ctx);
    
    return result;
}

unsigned char* RA::ASE_dec(unsigned char* key, unsigned char* data, 
                          size_t data_len, unsigned char* assocData) {
    // 初始化解密上下文
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);
    
    // 设置GCM模式
    EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, key, Parameter::nonce);
    
    // 设置关联数据
    EVP_DecryptUpdate(ctx, nullptr, nullptr, assocData, 16);
    
    // 分离密文和标签
    unsigned char* ciphertext = (unsigned char*)malloc(data_len - 16);
    unsigned char tag[16];
    
    memcpy(ciphertext, data, data_len - 16);
    memcpy(tag, data + data_len - 16, 16);
    
    // 设置认证标签
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
    
    // 解密数据
    int outlen1, outlen2;
    unsigned char* outbuf = (unsigned char*)malloc(data_len);
    
    EVP_DecryptUpdate(ctx, outbuf, &outlen1, ciphertext, data_len - 16);
    EVP_DecryptFinal_ex(ctx, outbuf + outlen1, &outlen2);
    
    // 调整输出大小
    unsigned char* result = (unsigned char*)malloc(outlen1 + outlen2);
    memcpy(result, outbuf, outlen1 + outlen2);
    
    // 释放资源
    free(outbuf);
    free(ciphertext);
    EVP_CIPHER_CTX_free(ctx);
    
    return result;
}

std::vector<unsigned char*> RA::Join(EVP_CIPHER_CTX* ks, const std::string& ID, long time) {
    std::vector<unsigned char*> Ax(2);
    
    // Ks字节数组
    IDLG[alpha] = ID;
    Ax[0] = DGTOTP_PRF::ksAES(G + "KS" + std::to_string(alpha), ks_cipher);
    
    // alpha ID索引字节数组
    Ax[1] = intToBytes(alpha);
    
    alpha++;
    
    return Ax;
}

int RA::Revoke(const std::string& ID, EVP_CIPHER_CTX* RA_key) {
    per_id_index = 0;
    int result = 0;
    
    for (int i = 0; i < IDLG.size(); i++) {
        if (IDLG[i] == ID) {
            per_id_index = i;
            result = 1;
            break;
        }
    }
    
    RL[per_id_index] = 1;
    
    return result;
}