#include "Member.h"
#include "Parameter.h"
#include "TOTP.h"
#include "ChameleonHash.h"
#include "DGTOTP_PRF.h"
#include "RA.h"
#include <cstring>
#include <sstream>
#include <iomanip>
#include <openssl/rand.h>
#include <gmp.h>

// 静态成员初始化
unsigned char* Member::alpha = nullptr;
int Member::k = 0;
int Member::N = 0;
int Member::E = 0;
long Member::START_TIME = 0;
long Member::END_TIME = 0;
int Member::Δs = 0;
int Member::Δe = 0;

Member::Member() {
    cache_byte = nullptr;
    memset(cache_32, 0, 32);
    rand = (unsigned char*)malloc(32);
    memset(rand, 0, 32);
    chame_hash = nullptr;
    SECRET_KEY = nullptr;
    ks = nullptr;
    ks_cipher = nullptr;
    key_cipher = nullptr;
}

Member::~Member() {
    if (cache_byte != nullptr) {
        free(cache_byte);
    }
    
    if (rand != nullptr) {
        free(rand);
    }
    
    if (chame_hash != nullptr) {
        delete chame_hash;
    }
    
    if (SECRET_KEY != nullptr) {
        EVP_CIPHER_CTX_free(SECRET_KEY);
    }
    
    if (ks != nullptr) {
        EVP_CIPHER_CTX_free(ks);
    }
    
    if (ks_cipher != nullptr) {
        EVP_CIPHER_CTX_free(ks_cipher);
    }
    
    if (key_cipher != nullptr) {
        EVP_CIPHER_CTX_free(key_cipher);
    }
}

void Member::PInit(const std::string& ID) {
    // 参数初始化
    START_TIME = Parameter::START_TIME;
    END_TIME = Parameter::END_TIME;
    E = Parameter::E;
    N = Parameter::N;
    k = Parameter::k;
    Δs = Parameter::Δs;
    Δe = Parameter::Δe;
    
    // 生成密钥
    SECRET_KEY = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(SECRET_KEY);
    
    unsigned char key[16];
    RAND_bytes(key, 16);
    
    // 初始化加密上下文
    key_cipher = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(key_cipher);
    EVP_EncryptInit_ex(key_cipher, EVP_aes_128_ecb(), nullptr, key, nullptr);
    
    ID_MENBER = ID;
}

unsigned char* Member::GetSD(EVP_CIPHER_CTX* SECRET_KEY, long time) {
    int chain_index = (int)((time - START_TIME) / Δe);
    
    // 生成密码种子
    std::string input = ID_MENBER + std::to_string(chain_index);
    unsigned char* part1 = DGTOTP_PRF::ksAES(input, key_cipher);
    unsigned char* part2 = DGTOTP_PRF::ksAES(input, key_cipher);
    
    unsigned char* result = Parameter::byteMerger(part1, 16, part2, 16);
    
    free(part1);
    free(part2);
    
    return result;
}

std::vector<std::string> Member::PwGen(std::vector<unsigned char*>& Ax, long time) {
    // DGTOTP密码
    std::vector<std::string> DGTOTP_pw(3);
    int instance_index = (int)((time - START_TIME) / Δe);
    
    if (!SECRET_SEED.empty()) {
        cache_string = SECRET_SEED;
    } else {
        unsigned char* sd = GetSD(SECRET_KEY, time);
        cache_string = byte2hex(sd, 32);
        SECRET_SEED = cache_string;
        free(sd);
    }
    
    // 密码索引z
    long pw_sequence = (time - instance_index * Δe - START_TIME) / Δs;
    
    // TOTP密码
    cache_string = TOTP::PGen(cache_string, pw_sequence);
    DGTOTP_pw[0] = cache_string;
    
    // 成员缓存变色龙哈希碰撞和身份密文
    if (rand != nullptr && !cipher_id.empty()) {
        DGTOTP_pw[2] = cipher_id;
        DGTOTP_pw[1] = std::string(reinterpret_cast<char*>(rand), 32);
        return DGTOTP_pw;
    }
    
    // 成员ks
    ks = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ks);
    EVP_EncryptInit_ex(ks, EVP_aes_128_ecb(), nullptr, Ax[0], nullptr);
    
    ks_cipher = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ks_cipher);
    EVP_EncryptInit_ex(ks_cipher, EVP_aes_128_ecb(), nullptr, Ax[0], nullptr);
    
    // ke加密密钥
    cache_byte = DGTOTP_PRF::ksAES("KeyGen" + std::to_string(instance_index), ks_cipher);
    
    // 生成re
    unsigned char* re = DGTOTP_PRF::ksAES("Rand" + std::to_string(instance_index), ks_cipher);
    
    // ID的转换身份
    alpha = Ax[1];
    
    // 身份密文
    unsigned char* cipher = RA::ASE_enc(Ax[1], 4, cache_byte, re);
    DGTOTP_pw[2] = std::string(reinterpret_cast<char*>(cipher), 16);
    cipher_id = DGTOTP_pw[2];
    
    // 变色龙哈希sk
    unsigned char* part1 = DGTOTP_PRF::ksAES(Parameter::G + "CHR" + std::to_string(instance_index), ks_cipher);
    unsigned char* part2 = DGTOTP_PRF::ksAES(Parameter::G + "CHR" + std::to_string(instance_index), ks_cipher);
    memcpy(cache_32, Parameter::byteMerger(part1, 16, part2, 16), 32);
    
    // 获取验证点
    unsigned char* cache_tem = TOTP::toBytes(DGTOTP_pw[0]);
    for (int i = 0; i < pw_sequence + 1; i++) {
        unsigned char* temp = Parameter::Sha256(cache_tem, 32);
        memcpy(cache_tem, temp, 32);
        free(temp);
    }
    
    // 获取TOTP的验证点
    std::string vp = byte2hex(cache_tem, 32);
    
    // vp'
    unsigned char* verify_point = Parameter::Sha256(vp + DGTOTP_pw[2] + std::to_string(instance_index));
    
    // 虚拟验证点
    unsigned char* part3 = DGTOTP_PRF::ksAES(Parameter::G + "DVP" + std::to_string(instance_index), ks_cipher);
    unsigned char* part4 = DGTOTP_PRF::ksAES(Parameter::G + "DVP" + std::to_string(instance_index), ks_cipher);
    unsigned char* dvp = Parameter::byteMerger(part3, 16, part4, 16);
    
    // rand
    unsigned char* part5 = DGTOTP_PRF::ksAES(Parameter::G + "DR" + std::to_string(instance_index), ks_cipher);
    unsigned char* part6 = DGTOTP_PRF::ksAES(Parameter::G + "DR" + std::to_string(instance_index), ks_cipher);
    unsigned char* rd = Parameter::byteMerger(part5, 16, part6, 16);
    
    // 变色龙哈希碰撞
    mpz_t sk;
    mpz_init(sk);
    mpz_import(sk, 32, 1, 1, 0, 0, cache_32);
    
    unsigned char* r = ChameleonHash::Collision(dvp, 32, rd, 32, verify_point, 32, sk);
    memcpy(rand, r, 32);
    
    // 字节数组 -> 字符串
    DGTOTP_pw[1] = std::string(reinterpret_cast<char*>(r), 32);
    
    // 释放资源
    free(cache_tem);
    free(verify_point);
    free(dvp);
    free(rd);
    free(r);
    free(re);
    free(cipher);
    free(part1);
    free(part2);
    free(part3);
    free(part4);
    free(part5);
    free(part6);
    mpz_clear(sk);
    
    return DGTOTP_pw;
}

std::string Member::byte2hex(const unsigned char* b, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0');
    
    for (size_t i = 0; i < len; i++) {
        ss << std::setw(2) << static_cast<int>(b[i]);
    }
    
    return ss.str();
}