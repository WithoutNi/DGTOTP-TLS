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
    /// Number of group members
    static int U;

    /// Security parameter
    static int k;

    /// Number of passwords in TOTP instance
    static int N;

    /// Number of TOTP protocol instances
    static int E;

    /// Start time (timestamp)
    static long START_TIME;

    /// End time (timestamp)
    static long END_TIME;

    /// Verification period (Δe)
    static int Δe;

    /// Password generation period (Δs)
    static int Δs;

    /// Chameleon hash instance pointer
    static ChameleonHash *chame_hash;

    /// SHA256 digest context
    static EVP_MD_CTX *digest;

    /// Group instance identifier or representation
    static std::string G;

    /// AES encryption context
    static EVP_CIPHER_CTX *AesCipher;

    /// AES-GCM nonce
    static unsigned char *nonce;

    /// Chameleon hash values vector (V)
    static std::vector<int> CH_hash;

    /// Member identity ciphertexts
    static std::vector<std::string> Member_cipher;

    /// Chameleon hash public keys
    static std::vector<EC_POINT *> CH_key;

    /// Merkle proofs
    static std::vector<std::string> merkle_proof;

    /// Proof length
    static int proof_len;

    /// Group public key
    static std::string gpk;

    /// Initialize system parameters
    static void init();

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

    /// Clean up allocated resources
    static void cleanup();
};

#endif // PARAMETER_H