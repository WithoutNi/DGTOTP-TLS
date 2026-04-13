#ifndef TOTP_H
#define TOTP_H

#include <string>
#include <openssl/sha.h>
#include <openssl/evp.h>

/**
 * TOTP class - Time-based One-Time Password algorithm
 */
class TOTP
{
public:
    /// Security parameter
    static int k;

    /// Number of passwords in TOTP instance
    static int N;

    /// TOTP instance start time
    static long Δs;

    /// TOTP instance end time
    static long Δe;

    /// Verification point
    static std::string VERIFY_POINT;

    /// Password seed
    static std::string SK_SEED;

    /// SHA256 context
    static EVP_MD_CTX *digest;

    /// SHA256 hash result
    static unsigned char sha256[32];

    /// Cache byte array
    static unsigned char *cache_byte;

    /// Generate seed from key
    /// @param[in] key Input key
    static void getSeed(const std::string &key);

    /// Configure TOTP parameters
    /// @param[in] k          Security parameter
    /// @param[in] START_TIME Start time
    /// @param[in] END_TIME   End time
    /// @param[in] PASS_GEN   Password generation period
    static void Setup(int k, long START_TIME, long END_TIME, long PASS_GEN);

    /// Initialize TOTP instance
    /// @param[in] SK_SEED Password seed
    /// @return Verification point
    static std::string PInit(const std::string &SK_SEED);

    /// Generate TOTP password
    /// @param[in] SK_SEED      Password seed
    /// @param[in] pw_sequence  Password sequence number
    /// @return Generated TOTP password
    static std::string PGen(const std::string &SK_SEED, long pw_sequence);

    /// Verify TOTP password
    /// @param[in] VERIFY_POINT Verification point
    /// @param[in] password     Password to verify
    /// @param[in] pw_sequence  Password sequence number
    /// @return Verification result (1 success, 0 failure)
    static int Verify(const std::string &VERIFY_POINT, const std::string &password, long pw_sequence);

    /// Convert byte array to hexadecimal string
    /// @param[in] b   Byte array
    /// @param[in] len Array length
    /// @return Hexadecimal string
    static std::string byte2hex(const unsigned char *b, size_t len);

    /// Convert hexadecimal string to byte array
    /// @param[in] str Hexadecimal string
    /// @return Byte array
    static unsigned char *toBytes(const std::string &str);

    /// SHA256 hash function - byte array version
    /// @param[in] tem Input message bytes
    /// @param[in] len Message length
    /// @return Hash result
    static unsigned char *Hash_Sha256(const unsigned char *tem, size_t len);

    /// SHA256 hash function - string version
    /// @param[in] message Input message string
    /// @return Hash result
    static unsigned char *Hash_Sha256(const std::string &message);

    /// Free cache byte array memory
    static void freeCacheByte();
};

#endif // TOTP_H