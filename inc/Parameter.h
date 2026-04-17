#ifndef PARAMETER_H
#define PARAMETER_H

#include <string>
#include <vector>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <iostream>
#include <sstream>
#include <iomanip>

// Forward declaration
class ChameleonHash;

/**
 * Parameter class - Stores and initializes DGTOTP system parameters
 */
class Parameter
{
public:
    // ===================== Constructor/Destructor =====================

    /// Constructor
    Parameter();

    /// Destructor
    ~Parameter();

    // ===================== Modify Methods =====================

    /// Initialize system parameters using the current local time
    /// @param[in] groupId group identifier
    void init(const std::string &groupId = "DGTOTP");

    /// Initialize system parameters using an explicit shared start time
    /// @param[in] groupId        group identifier
    /// @param[in] startTimestamp shared protocol start time in milliseconds
    void init(const std::string &groupId, long startTimestamp);

    /// Clean up allocated resources
    void cleanup();

    /// Set number of group members
    /// @param[in] memberNum Number of group members
    void setU(int memberNum);

    /// Set security parameter
    /// @param[in] securityParameter Security parameter value
    void setK(int securityParameter);

    /// Set number of passwords in TOTP instance
    /// @param[in] pwNum Number of passwords
    void setN(int pwNum);

    /// Set number of TOTP protocol instances
    /// @param[in] totpNum Number of TOTP instances
    void setE(int totpNum);

    /// Set start time
    /// @param[in] startTimestamp Start time timestamp
    void setStartTime(long startTimestamp);

    /// Set end time
    /// @param[in] endTimestamp End time timestamp
    void setEndTime(long endTimestamp);

    /// Set verification period
    /// @param[in] verificationPeriod Verification period value
    void setDeltaE(int verificationPeriod);

    /// Set password generation period
    /// @param[in] generationPeriod Password generation period value
    void setDeltaS(int generationPeriod);

    /// Set chameleon hash instance
    /// @param[in] chameleon Chameleon hash instance pointer
    void setChameHash(ChameleonHash *chameleon);

    /// Set digest context
    /// @param[in] digestContext Digest context pointer
    void setDigest(EVP_MD_CTX *digestContext);

    /// Set group instance identifier
    /// @param[in] groupName Group instance identifier
    void setG(const std::string &groupName);

    /// Set AES encryption context
    /// @param[in] aesContext AES encryption context pointer
    void setAesCipher(EVP_CIPHER_CTX *aesContext);

    /// Set AES-GCM nonce
    /// @param[in] nonce AES-GCM nonce pointer
    void setNonce(unsigned char *nonce);

    /// Set chameleon hash values vector
    /// @param[in] chamelonValues Chameleon hash values vector
    void setChHash(const std::vector<int> &chamelonValues);

    /// Set member identity ciphertexts
    /// @param[in] memberCiphertexts Member identity ciphertexts vector
    void setMemberCipher(const std::vector<std::string> &memberCiphertexts);

    /// Set chameleon hash public keys
    /// @param[in] chamelonPKVec Chameleon hash public keys vector
    void setChKey(const std::vector<EC_POINT *> &chamelonPKVec);

    /// Set merkle proofs
    /// @param[in] merklrProofsVec Merkle proofs vector
    void setMerkleProof(const std::vector<std::string> &merklrProofsVec);

    /// Set proof length
    /// @param[in] proofLength Proof length value
    void setProofLen(int proofLength);

    /// Set group public key
    /// @param[in] groupPublicKey Group public key string
    void setGpk(const std::string &groupPublicKey);

    // ===================== Access Methods =====================

    /// Get number of group members
    /// @return Number of group members
    int getU() const;

    /// Get security parameter
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

    /// Get verification period
    /// @return Verification period
    int getDeltaE() const;

    /// Get password generation period
    /// @return Password generation period
    int getDeltaS() const;

    /// Get chameleon hash instance
    /// @return Chameleon hash instance
    ChameleonHash *getChameHash() const;

    /// Get digest context
    /// @return Digest context
    EVP_MD_CTX *getDigest() const;

    /// Get group instance identifier
    /// @return Group instance identifier
    std::string getG() const;

    /// Get AES encryption context
    /// @return AES encryption context
    EVP_CIPHER_CTX *getAesCipher() const;

    /// Get AES-GCM nonce
    /// @return AES-GCM nonce
    unsigned char *getNonce() const;

    /// Get chameleon hash values vector
    /// @return Chameleon hash values vector
    const std::vector<int> &getChHash() const;

    /// Get member identity ciphertexts
    /// @return Member identity ciphertexts
    const std::vector<std::string> &getMemberCipher() const;

    /// Get chameleon hash public keys
    /// @return Chameleon hash public keys
    const std::vector<EC_POINT *> &getChKey() const;

    /// Get merkle proofs
    /// @return Merkle proofs
    const std::vector<std::string> &getMerkleProof() const;

    /// Get proof length
    /// @return Proof length
    int getProofLen() const;

    /// Get group public key
    /// @return Group public key
    std::string getGpk() const;

    // ===================== Static Methods =====================

    /// SHA256 hash function - byte array version
    /// @param[in] message Input message
    /// @param[in] length  Message length
    /// @return Hash result
    static unsigned char *Sha256(unsigned char *message, size_t length);

    /// SHA256 hash function - string version
    /// @param[in] message Input message string
    /// @return Hash result
    static unsigned char *Sha256(const std::string &message);

    /// Convert byte array to integer
    /// @param[in] bytes Byte array
    /// @return Integer value
    static int bytesToInt(unsigned char *bytes);

    /// Merge two byte arrays
    /// @param[in] byte_1     First byte array
    /// @param[in] byte_1_len Length of first byte array
    /// @param[in] byte_2     Second byte array
    /// @param[in] byte_2_len Length of second byte array
    /// @return Merged byte array
    static unsigned char *byteMerger(unsigned char *byte_1, size_t byte_1_len,
                                     unsigned char *byte_2, size_t byte_2_len);

    /// Convert integer to byte array
    /// @param[in] i Integer value
    /// @return Byte array
    static unsigned char *intToBytes(int i);

private:
    // ===================== Member Variables =====================

    /// Number of group members
    int U;

    /// Security parameter
    int k;

    /// Number of passwords in TOTP instance
    int N;

    /// Number of TOTP protocol instances
    int E;

    /// Start time (timestamp)
    long START_TIME;

    /// End time (timestamp)
    long END_TIME;

    /// Verification period (Δe)
    int Δe;

    /// Password generation period (Δs)
    int Δs;

    /// Chameleon hash instance pointer
    ChameleonHash *chame_hash;

    /// SHA256 digest context
    EVP_MD_CTX *digest;

    /// Group instance identifier or representation
    std::string G;

    /// AES encryption context
    EVP_CIPHER_CTX *AesCipher;

    /// Chameleon hash values vector (V)
    std::vector<int> CH_hash;

    /// Member identity ciphertexts
    std::vector<std::string> Member_cipher;

    /// Chameleon hash public keys
    std::vector<EC_POINT *> CH_key;

    /// Merkle proofs
    std::vector<std::string> merkle_proof;

    /// Proof length
    int proof_len;

    /// Group public key
    std::string gpk;

    /// AES-GCM nonce
    unsigned char *nonce;
};

#endif // PARAMETER_H
