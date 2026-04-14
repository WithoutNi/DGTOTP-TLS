#ifndef TOTP_H
#define TOTP_H

#include <string>
#include <openssl/sha.h>
#include <openssl/evp.h>

// Forward declaration
class Parameter;

/**
 * TOTP class - Time-based One-Time Password algorithm
 */
class TOTP
{
public:
    // ===================== Constructor/Destructor =====================

    /// Constructor
    TOTP();

    /// Destructor
    ~TOTP();

    // ===================== Modify Methods =====================

    /// Configure TOTP parameters
    /// @param[in] params Parameter instance
    void Setup(Parameter &params);

    /// Initialize TOTP instance
    /// @param[in] SK_SEED Password seed
    /// @return Verification point
    std::string PInit(const std::string &SK_SEED);

    /// Generate TOTP password
    /// @param[in] SK_SEED      Password seed
    /// @param[in] pw_sequence  Password sequence number
    /// @return Generated TOTP password
    std::string PGen(const std::string &SK_SEED, long pw_sequence);

    /// Verify TOTP password
    /// @param[in] VERIFY_POINT Verification point
    /// @param[in] password     Password to verify
    /// @param[in] pw_sequence  Password sequence number
    /// @return Verification result (1 success, 0 failure)
    int Verify(const std::string &VERIFY_POINT, const std::string &password, long pw_sequence);

    // ===================== Access Methods =====================

    /// Get security parameter
    /// @return Security parameter
    int getK() const;

    /// Get number of passwords in TOTP instance
    /// @return Number of passwords
    int getN() const;

    /// Get TOTP instance start time
    /// @return Start time
    long getDeltaS() const;

    /// Get TOTP instance end time
    /// @return End time
    long getDeltaE() const;

    /// Get verification point
    /// @return Verification point
    std::string getVerifyPoint() const;

    /// Get password seed
    /// @return Password seed
    std::string getSkSeed() const;

    /// Get SHA256 context
    /// @return SHA256 context
    EVP_MD_CTX *getDigest() const;

    /// Get SHA256 hash result
    /// @return SHA256 hash result
    const unsigned char *getSha256() const;

    /// Get cache byte array
    /// @return Cache byte array
    unsigned char *getCacheByte() const;

    /// Free cache byte array memory
    void freeCacheByte();

    // ===================== Static Methods =====================

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

private:
    // ===================== Member Variables =====================

    /// Security parameter
    int k;

    /// Number of passwords in TOTP instance
    int N;

    /// TOTP instance start time
    long Δs;

    /// TOTP instance end time
    long Δe;

    /// Verification point
    std::string VERIFY_POINT;

    /// Password seed
    std::string SK_SEED;

    /// SHA256 context
    EVP_MD_CTX *digest;

    /// SHA256 hash result
    unsigned char sha256[32];

    /// Cache byte array
    unsigned char *cache_byte;
};

#endif // TOTP_H