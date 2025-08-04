#include "ChameleonHash.h"
#include <cstring>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>

// 静态成员初始化
EC_POINT* ChameleonHash::G = nullptr;
mpz_t ChameleonHash::p;
mpz_t ChameleonHash::N;
EC_GROUP* ChameleonHash::group = nullptr;

ChameleonHash::ChameleonHash() {
    mpz_init(sk);
    pk = nullptr;
}

ChameleonHash::~ChameleonHash() {
    mpz_clear(sk);
    if (pk != nullptr) {
        EC_POINT_free(pk);
    }
}

void ChameleonHash::init() {
    // 初始化椭圆曲线参数
    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1); // secp256r1
    
    // 获取基点G
    G = EC_POINT_new(group);
    EC_POINT_copy(G, EC_GROUP_get0_generator(group));
    
    // 获取阶N
    BIGNUM* order = BN_new();
    EC_GROUP_get_order(group, order, nullptr);
    mpz_init(N);
    mpz_import(N, BN_num_bytes(order), 1, 1, 0, 0, BN_bn2hex(order));
    BN_free(order);
    
    // 设置有限域P
    mpz_init_set_str(p, "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16);
}

void ChameleonHash::Setup(unsigned char* rk) {
    // 设置私钥sk
    mpz_t temp;
    mpz_init(temp);
    mpz_import(temp, 32, 1, 1, 0, 0, rk);
    mpz_mod(sk, temp, N);
    mpz_clear(temp);
    
    // 计算公钥pk = sk * G
    BIGNUM* sk_bn = BN_new();
    unsigned char sk_bytes[32];
    size_t count;
    mpz_export(sk_bytes, &count, 1, 1, 0, 0, sk);
    BN_bin2bn(sk_bytes, count, sk_bn);
    
    pk = EC_POINT_new(group);
    EC_POINT_mul(group, pk, sk_bn, nullptr, nullptr, nullptr);
    
    BN_free(sk_bn);
}

void ChameleonHash::getRand(mpz_t result) {
    mpz_init(result);
    
    unsigned char data[32];
    RAND_bytes(data, 32);
    
    mpz_import(result, 32, 1, 1, 0, 0, data);
    mpz_mod(result, result, p);
}

int ChameleonHash::eval(unsigned char* msg, size_t msg_len, EC_POINT* pk, unsigned char* rand, size_t rand_len) {
    // 将消息转换为大整数
    BIGNUM* Big_msg = BN_new();
    BN_bin2bn(msg, msg_len, Big_msg);
    
    // 将随机数转换为大整数
    BIGNUM* Big_rand = BN_new();
    BN_bin2bn(rand, rand_len, Big_rand);
    
    // 计算T1 = msg * pk
    EC_POINT* T1 = EC_POINT_new(group);
    EC_POINT_mul(group, T1, nullptr, pk, Big_msg, nullptr);
    
    // 计算T2 = rand * G
    EC_POINT* T2 = EC_POINT_new(group);
    EC_POINT_mul(group, T2, Big_rand, nullptr, nullptr, nullptr);
    
    // 计算T1 + T2
    EC_POINT* result = EC_POINT_new(group);
    EC_POINT_add(group, result, T1, T2, nullptr);
    
    // 计算哈希值
    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, result, x, y, nullptr);
    
    // 使用x和y坐标的组合作为哈希值
    char* x_hex = BN_bn2hex(x);
    char* y_hex = BN_bn2hex(y);
    std::string hash_str = std::string(x_hex) + std::string(y_hex);
    int hash_value = std::hash<std::string>{}(hash_str);
    
    // 释放资源
    OPENSSL_free(x_hex);
    OPENSSL_free(y_hex);
    BN_free(x);
    BN_free(y);
    BN_free(Big_msg);
    BN_free(Big_rand);
    EC_POINT_free(T1);
    EC_POINT_free(T2);
    EC_POINT_free(result);
    
    return abs(hash_value);
}

int ChameleonHash::Verify(unsigned char* msg1, size_t msg1_len, unsigned char* r1, size_t r1_len, 
                          EC_POINT* pk, int CH2) {
    int result = 0;
    int CH1 = eval(msg1, msg1_len, pk, r1, r1_len);
    
    if (CH1 == CH2) {
        return 1;
    }
    
    return result;
}

unsigned char* ChameleonHash::Collision(unsigned char* msg1, size_t msg1_len, 
                                       unsigned char* r1, size_t r1_len, 
                                       unsigned char* msg2, size_t msg2_len, 
                                       mpz_t sk) {
    // 将消息1转换为大整数
    mpz_t Big_msg1;
    mpz_init(Big_msg1);
    mpz_import(Big_msg1, msg1_len, 1, 1, 0, 0, msg1);
    
    // 将随机数r1转换为大整数
    mpz_t Big_r1;
    mpz_init(Big_r1);
    mpz_import(Big_r1, r1_len, 1, 1, 0, 0, r1);
    
    // 将消息2转换为大整数
    mpz_t Big_msg2;
    mpz_init(Big_msg2);
    mpz_import(Big_msg2, msg2_len, 1, 1, 0, 0, msg2);
    
    // 计算r2 = sk*m1 + r1 - m2*sk mod N
    mpz_t r2, temp1, temp2;
    mpz_init(r2);
    mpz_init(temp1);
    mpz_init(temp2);
    
    mpz_mul(temp1, sk, Big_msg1);      // temp1 = sk * m1
    mpz_add(temp2, temp1, Big_r1);      // temp2 = sk * m1 + r1
    mpz_mul(temp1, sk, Big_msg2);      // temp1 = sk * m2
    mpz_sub(r2, temp2, temp1);         // r2 = sk * m1 + r1 - sk * m2
    mpz_mod(r2, r2, N);                // r2 = r2 mod N
    
    // 将r2转换为字节数组
    size_t count;
    unsigned char* result = (unsigned char*)malloc(32);
    mpz_export(result, &count, 1, 1, 0, 0, r2);
    
    // 释放资源
    mpz_clear(Big_msg1);
    mpz_clear(Big_r1);
    mpz_clear(Big_msg2);
    mpz_clear(r2);
    mpz_clear(temp1);
    mpz_clear(temp2);
    
    return result;
}