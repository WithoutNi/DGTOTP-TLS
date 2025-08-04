#include "TOTP.h"
#include "Parameter.h"
#include <cstring>
#include <sstream>
#include <iomanip>

// 静态成员初始化
int TOTP::k = Parameter::k;
int TOTP::N = Parameter::N;
long TOTP::Δs = Parameter::Δs;
long TOTP::Δe = Parameter::Δe;
std::string TOTP::VERIFY_POINT = "";
std::string TOTP::SK_SEED = "";
EVP_MD_CTX* TOTP::digest = nullptr;
unsigned char TOTP::sha256[32] = {0};
unsigned char* TOTP::cache_byte = nullptr;

void TOTP::getSeed(const std::string& key) {
    std::string test = "testing";
    SK_SEED = byte2hex(Hash_Sha256(test), 32);
}

void TOTP::Setup(int k, long START_TIME, long END_TIME, long PASS_GEN) {
    N = (int)((END_TIME - START_TIME) / PASS_GEN);
}

std::string TOTP::PInit(const std::string& SK_SEED) {
    cache_byte = toBytes(SK_SEED);
    for (int i = 1; i <= N; i++) {
        unsigned char* temp = Hash_Sha256(cache_byte, 32);
        memcpy(cache_byte, temp, 32);
        free(temp);
    }
    VERIFY_POINT = byte2hex(cache_byte, 32);
    return byte2hex(cache_byte, 32);
}

std::string TOTP::PGen(const std::string& SK_SEED, long pw_sequence) {
    cache_byte = toBytes(SK_SEED);
    for (int i = 0; i < N - pw_sequence - 1; i++) {
        unsigned char* temp = Hash_Sha256(cache_byte, 32);
        memcpy(cache_byte, temp, 32);
        free(temp);
    }
    return byte2hex(cache_byte, 32);
}

int TOTP::Verify(const std::string& VERIFY_POINT, const std::string& password, long pw_sequence) {
    int check_out = 0;
    cache_byte = toBytes(password);
    
    for (int i = 0; i < pw_sequence + 1; i++) {
        unsigned char* temp = Hash_Sha256(cache_byte, 32);
        memcpy(cache_byte, temp, 32);
        free(temp);
    }
    
    if (byte2hex(cache_byte, 32) == VERIFY_POINT) {
        check_out = 1;
    }
    
    return check_out;
}

std::string TOTP::byte2hex(const unsigned char* b, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0');
    
    for (size_t i = 0; i < len; i++) {
        ss << std::setw(2) << static_cast<int>(b[i]);
    }
    
    return ss.str();
}

unsigned char* TOTP::toBytes(const std::string& str) {
    if (str.empty()) {
        return (unsigned char*)malloc(0);
    }
    
    size_t len = str.length() / 2;
    unsigned char* bytes = (unsigned char*)malloc(len);
    
    for (size_t i = 0; i < len; i++) {
        std::string byteString = str.substr(i * 2, 2);
        bytes[i] = (unsigned char)strtol(byteString.c_str(), nullptr, 16);
    }
    
    return bytes;
}

unsigned char* TOTP::Hash_Sha256(const unsigned char* tem, size_t len) {
    unsigned char* result = (unsigned char*)malloc(32);
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    
    EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(mdctx, tem, len);
    EVP_DigestFinal_ex(mdctx, result, nullptr);
    
    EVP_MD_CTX_free(mdctx);
    return result;
}

unsigned char* TOTP::Hash_Sha256(const std::string& message) {
    return Hash_Sha256((const unsigned char*)message.c_str(), message.length());
}