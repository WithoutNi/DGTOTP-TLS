#ifndef MEMBER_H
#define MEMBER_H

#include <string>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <vector>

// Forward declaration
class ChameleonHash;

/// Member class - Implements group member functionality
class Member
{
public:
    /// Member identifier string
    std::string ID_MENBER;

    /// ID transformation identity bytes
    static unsigned char *alpha;

    /// Encryption key context (kt)
    EVP_CIPHER_CTX *SECRET_KEY;

    /// Security parameter k
    static int k;

    /// Number of passwords in TOTP instance
    static int N;

    /// Number of TOTP protocol instances
    static int E;

    /// Start time (timestamp)
    static long START_TIME;

    /// End time (timestamp)
    static long END_TIME;

    /// Password generation period (delta s)
    static int Δs;

    /// Verification period (delta e)
    static int Δe;

    /// Secret seed string sd
    std::string SECRET_SEED;

    /// Identity ciphertext string
    std::string cipher_id;

    /// 16-byte cache buffer
    unsigned char *cache_byte;

    /// 32-byte cache buffer
    unsigned char cache_32[32];

    /// String cache
    std::string cache_string;

    /// Key ks context
    EVP_CIPHER_CTX *ks;

    /// Encryption context for key ks
    EVP_CIPHER_CTX *ks_cipher;

    /// Encryption context for key kt
    EVP_CIPHER_CTX *key_cipher;

    /// Chameleon hash instance pointer
    ChameleonHash *chame_hash;

    /// Chameleon hash collision random bytes
    unsigned char *rand;

    /// Constructor
    Member();

    /// Destructor
    ~Member();

    /// Initialize member
    /// @param[in] ID Member ID
    void PInit(const std::string &ID);

    /// Get password seed for current verification period
    /// @param[in] SECRET_KEY Encryption key
    /// @param[in] time Current time
    unsigned char *GetSD(EVP_CIPHER_CTX *SECRET_KEY, long time);

    /// Generate passwords
    /// @param[in] Ax Parameters
    /// @param[in] time Current time
    std::vector<std::string> PwGen(std::vector<unsigned char *> &Ax, long time);

    /// Convert byte array to hexadecimal string
    /// @param[in] b Byte array
    /// @param[in] len Array length
    static std::string byte2hex(const unsigned char *b, size_t len);
};

#endif // MEMBER_H