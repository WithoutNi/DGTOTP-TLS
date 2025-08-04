#include "Parameter.h"
#include "ChameleonHash.h"
#include <cstring>
#include <openssl/rand.h>
#include <openssl/evp.h>

// 静态成员初始化
int Parameter::U = 0;
int Parameter::k = 128;
int Parameter::N = 60;
int Parameter::E = 0;
long Parameter::START_TIME = 0;
long Parameter::END_TIME = 0;
int Parameter::Δe = 300000;
int Parameter::Δs = 5000;
ChameleonHash* Parameter::chame_hash = nullptr;
EVP_MD_CTX* Parameter::digest = nullptr;
std::string Parameter::G = "";
EVP_CIPHER_CTX* Parameter::AesCipher = nullptr;
unsigned char* Parameter::nonce = nullptr;
std::vector<int> Parameter::CH_hash;
std::vector<std::string> Parameter::Member_cipher;
std::vector<EC_POINT*> Parameter::CH_key;
std::vector<std::string> Parameter::merkle_proof;
int Parameter::proof_len = 0;
std::string Parameter::gpk = "";

void Parameter::init() {
    // 初始化OpenSSL
    OpenSSL_add_all_algorithms();
    
    G = "DGTOTP";
    
    // 初始化变色龙哈希
    chame_hash = new ChameleonHash();
    ChameleonHash::init();
    
    E = 100;
    U = 100;
    
    // 获取当前时间作为开始时间
    START_TIME = time(nullptr) * 1000; // 转换为毫秒
    END_TIME = START_TIME + E * Δe;
    N = 60;
    
    // 初始化SHA256上下文
    digest = EVP_MD_CTX_new();
    
    // 初始化向量
    Member_cipher.resize(U);
    CH_key.resize(U);
    CH_hash.resize(U);
    merkle_proof.resize(proof_len);
    
    // 初始化nonce
    nonce = (unsigned char*)malloc(12);
    const char* nonce_str = "202122232425262728292a2b2c";
    for (int i = 0; i < 12; i++) {
        sscanf(&nonce_str[i*2], "%2hhx", &nonce[i]);
    }
    
    // 初始化AES加密上下文
    AesCipher = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(AesCipher);
}

unsigned char* Parameter::Sha256(unsigned char* message, size_t length) {
    unsigned char* sha256Bytes = (unsigned char*)malloc(32);
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    
    EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(mdctx, message, length);
    EVP_DigestFinal_ex(mdctx, sha256Bytes, nullptr);
    
    EVP_MD_CTX_free(mdctx);
    return sha256Bytes;
}

unsigned char* Parameter::Sha256(const std::string& message) {
    return Sha256((unsigned char*)message.c_str(), message.length());
}

int Parameter::bytesToInt(unsigned char* bytes) {
    int i;
    i = (int)((bytes[0] & 0xff) | ((bytes[1] & 0xff) << 8) | 
             ((bytes[2] & 0xff) << 16) | ((bytes[3] & 0xff) << 24));
    return i;
}

unsigned char* Parameter::byteMerger(unsigned char* byte_1, size_t byte_1_len, 
                                    unsigned char* byte_2, size_t byte_2_len) {
    unsigned char* byte_3 = (unsigned char*)malloc(byte_1_len + byte_2_len);
    memcpy(byte_3, byte_1, byte_1_len);
    memcpy(byte_3 + byte_1_len, byte_2, byte_2_len);
    return byte_3;
}

unsigned char* Parameter::intToBytes(int i) {
    unsigned char* bytes = (unsigned char*)malloc(4);
    bytes[0] = (unsigned char)(i & 0xff);
    bytes[1] = (unsigned char)((i >> 8) & 0xff);
    bytes[2] = (unsigned char)((i >> 16) & 0xff);
    bytes[3] = (unsigned char)((i >> 24) & 0xff);
    return bytes;
}