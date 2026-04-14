#ifndef MEMBER_H
#define MEMBER_H

#include <string>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <vector>

// Forward declaration
class ChameleonHash;
class Parameter;

/// Member class - Implements group member functionality
class Member
{
public:
    /// Constructor
    Member();

    /// Destructor
    ~Member();

    /// Initialize member
    /// @param[in] ID Member ID
    /// @param[in] params Parameter instance
    void PInit(const std::string &ID, Parameter &params);

    /// Get password seed for current verification period
    /// @param[in] SECRET_KEY Encryption key
    /// @param[in] time Current time
    unsigned char *GetSD(EVP_CIPHER_CTX *SECRET_KEY, long time);

    /// Generate passwords
    /// @param[in] Ax Parameters
    /// @param[in] time Current time
    /// @param[in] params Parameter instance
    std::vector<std::string> PwGen(std::vector<unsigned char *> &Ax, long time, Parameter &params);

    /// Convert byte array to hexadecimal string
    /// @param[in] b Byte array
    /// @param[in] len Array length
    static std::string byte2hex(const unsigned char *b, size_t len);

    // ===================== Access Methods =====================

    /// Get security parameter k
    /// @return Security parameter
    int getK() const;

    /// Get number of passwords in TOTP instance
    /// @return Number of passwords
    int getN() const;

    /// Get number of TOTP protocol instances
    /// @return Number of TOTP instances
    int getE() const;

    /// Get start time
    /// @return Start time
    long getStartTime() const;

    /// Get end time
    /// @return End time
    long getEndTime() const;

    /// Get password generation period
    /// @return Password generation period
    int getDeltaS() const;

    /// Get verification period
    /// @return Verification period
    int getDeltaE() const;

    /// Get ID transformation identity bytes
    /// @return Alpha bytes
    unsigned char *getAlpha() const;

    /// Get Member identifier string
    std::string getID() const;

private:
    /// Member identifier string
    std::string ID_MENBER;

    /// ID transformation identity bytes
    unsigned char *alpha;

    /// Encryption key context (kt)
    EVP_CIPHER_CTX *SECRET_KEY;

    /// Security parameter k
    int k;

    /// Number of passwords in TOTP instance
    int N;

    /// Number of TOTP protocol instances
    int E;

    /// Start time (timestamp)
    long START_TIME;

    /// End time (timestamp)
    long END_TIME;

    /// Password generation period (delta s)
    int Δs;

    /// Verification period (delta e)
    int Δe;

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
};

#endif // MEMBER_H