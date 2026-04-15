#include "ChameleonHash.h"
#include <cstring>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <iostream>
#include <openssl/sha.h>

ChameleonHash::ChameleonHash()
{
    mpz_init(sk);
    mpz_init(p);
    mpz_init(N);
    G = nullptr;
    pk = nullptr;
    group = nullptr;
    init();
}

ChameleonHash::~ChameleonHash()
{
    cleanup();
    mpz_clear(sk);
    mpz_clear(p);
    mpz_clear(N);
}

void ChameleonHash::init()
{
    if (group != nullptr)
        return;

    // Use curve parameters
    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

    G = EC_POINT_new(group);
    EC_POINT_copy(G, EC_GROUP_get0_generator(group));

    // Get order N
    BIGNUM *order = BN_new();
    EC_GROUP_get_order(group, order, nullptr);

    // Convert BIGNUM to mpz_t
    unsigned char order_bytes[32];
    BN_bn2binpad(order, order_bytes, 32);
    mpz_import(N, 32, 1, 1, 0, 0, order_bytes);

    // Get finite field modulus p
    BIGNUM *p_bn = BN_new();
    EC_GROUP_get_curve_GFp(group, p_bn, nullptr, nullptr, nullptr);
    unsigned char p_bytes[32];
    BN_bn2binpad(p_bn, p_bytes, 32);
    mpz_import(p, 32, 1, 1, 0, 0, p_bytes);

    BN_free(order);
    BN_free(p_bn);
}

void ChameleonHash::Setup(unsigned char *rk)
{
    init();

    // Set private key sk
    mpz_t temp;
    mpz_init(temp);
    mpz_import(temp, 32, 1, 1, 0, 0, rk);
    mpz_mod(sk, temp, N);
    mpz_clear(temp);

    // Compute public key pk = sk * G
    BIGNUM *sk_bn = BN_new();
    unsigned char sk_bytes[32] = {0};
    size_t count;
    mpz_export(sk_bytes, &count, 1, 1, 0, 0, sk);
    if (count == 0)
    {
        BN_zero(sk_bn);
    }
    else
    {
        BN_bin2bn(sk_bytes, count, sk_bn);
    }

    if (pk != nullptr)
    {
        EC_POINT_free(pk);
    }

    pk = EC_POINT_new(group);
    EC_POINT_mul(group, pk, sk_bn, nullptr, nullptr, nullptr);

    BN_free(sk_bn);
}

void ChameleonHash::getRand(mpz_t result)
{
    unsigned char data[32];
    RAND_bytes(data, 32);

    mpz_import(result, 32, 1, 1, 0, 0, data);
    mpz_mod(result, result, p);
}

int ChameleonHash::eval(unsigned char *msg, size_t msg_len,
                        EC_POINT *pk, unsigned char *rand, size_t rand_len)
{
    init();

    if (!msg || !pk || !rand || !group)
        return 0;

    // Convert msg and rand to BIGNUM
    BIGNUM *m_bn = BN_bin2bn(msg, msg_len, nullptr);
    BIGNUM *r_bn = BN_bin2bn(rand, rand_len, nullptr);

    if (!m_bn || !r_bn)
    {
        if (m_bn)
            BN_free(m_bn);
        if (r_bn)
            BN_free(r_bn);
        return 0;
    }

    // Compute T = r*G + m*PK
    EC_POINT *T1 = EC_POINT_new(group);
    EC_POINT *T2 = EC_POINT_new(group);
    EC_POINT *T = EC_POINT_new(group);

    // T1 = m * PK
    EC_POINT_mul(group, T1, nullptr, pk, m_bn, nullptr);
    // T2 = r * G
    EC_POINT_mul(group, T2, r_bn, nullptr, nullptr, nullptr);
    // T = T1 + T2
    EC_POINT_add(group, T, T1, T2, nullptr);

    // Get coordinates
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, T, x, y, nullptr);

    // Compute hash
    unsigned char x_bytes[32], y_bytes[32];
    BN_bn2binpad(x, x_bytes, 32);
    BN_bn2binpad(y, y_bytes, 32);

    unsigned char hash[32];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, x_bytes, 32);
    SHA256_Update(&sha256, y_bytes, 32);
    SHA256_Final(hash, &sha256);

    // Convert to integer
    uint32_t result = (hash[0] << 24) | (hash[1] << 16) | (hash[2] << 8) | hash[3];

    // Clean up
    BN_free(m_bn);
    BN_free(r_bn);
    BN_free(x);
    BN_free(y);
    EC_POINT_free(T1);
    EC_POINT_free(T2);
    EC_POINT_free(T);

    return result & 0x7FFFFFFF; // Ensure positive
}

int ChameleonHash::Verify(unsigned char *msg1, size_t msg1_len, unsigned char *r1, size_t r1_len,
                          EC_POINT *pk, int CH2)
{
    int CH1 = eval(msg1, msg1_len, pk, r1, r1_len);

    if (CH1 == CH2)
    {
        return 1;
    }

    return 0;
}

unsigned char *ChameleonHash::Collision(unsigned char *msg1, size_t msg1_len,
                                        unsigned char *r1, size_t r1_len,
                                        unsigned char *msg2, size_t msg2_len,
                                        mpz_srcptr sk)
{
    // Convert messages and r1 to mpz_t
    mpz_t m1, m2, r1_mpz;
    mpz_init(m1);
    mpz_init(m2);
    mpz_init(r1_mpz);

    mpz_import(m1, msg1_len, 1, 1, 0, 0, msg1);
    mpz_import(m2, msg2_len, 1, 1, 0, 0, msg2);
    mpz_import(r1_mpz, r1_len, 1, 1, 0, 0, r1);

    // Compute r2 = r1 + sk*(m1 - m2) mod N
    mpz_t r2, temp;
    mpz_init(r2);
    mpz_init(temp);

    // temp = m1 - m2 mod N
    mpz_sub(temp, m1, m2);
    mpz_mod(temp, temp, N);

    // temp = sk * (m1 - m2) mod N
    mpz_mul(temp, sk, temp);
    mpz_mod(temp, temp, N);

    // r2 = r1 + sk*(m1 - m2) mod N
    mpz_add(r2, r1_mpz, temp);
    mpz_mod(r2, r2, N);

    // Convert to byte array
    size_t count;
    unsigned char *result = (unsigned char *)malloc(32);
    memset(result, 0, 32);

    // Get byte representation of r2
    mpz_export(result + (32 - mpz_sizeinbase(r2, 256)), &count, 1, 1, 0, 0, r2);

    // Clean up
    mpz_clear(m1);
    mpz_clear(m2);
    mpz_clear(r1_mpz);
    mpz_clear(r2);
    mpz_clear(temp);

    return result;
}

EC_POINT *ChameleonHash::clonePublicKey() const
{
    if (!pk)
        return nullptr;
    EC_POINT *new_pk = EC_POINT_new(group);
    EC_POINT_copy(new_pk, pk);
    return new_pk;
}

void ChameleonHash::cleanup()
{
    if (pk != nullptr)
    {
        EC_POINT_free(pk);
        pk = nullptr;
    }

    if (G != nullptr)
    {
        EC_POINT_free(G);
        G = nullptr;
    }

    // Clean EC_GROUP
    if (group != nullptr)
    {
        EC_GROUP_free(group);
        group = nullptr;
    }
}

mpz_srcptr ChameleonHash::getSk() const
{
    return sk;
}

EC_POINT *ChameleonHash::getG() const
{
    return G;
}

EC_POINT *ChameleonHash::getPk() const
{
    return pk;
}

mpz_srcptr ChameleonHash::getP() const
{
    return p;
}

mpz_srcptr ChameleonHash::getOrder() const
{
    return N;
}

EC_GROUP *ChameleonHash::getGroup() const
{
    return group;
}
