#ifndef DGTOTP_PRF_H
#define DGTOTP_PRF_H

#include <string>
#include <openssl/evp.h>

/**
 * DGTOTP_PRF class - Implements PRF for DGTOTP
 */
class DGTOTP_PRF
{
public:
    static EVP_CIPHER_CTX *cipher;

    /// Create a cryptographic key
    static unsigned char *createKey();

    /// AES encryption - JDK version
    /// @param[in] context     Input context string
    /// @param[in] originalKey Original encryption key
    static unsigned char *jdkAES(const std::string &context, unsigned char *originalKey);

    /// AES encryption - ks version
    /// @param[in] context Input context string
    /// @param[in] cipher  Encryption context
    static unsigned char *ksAES(const std::string &context, EVP_CIPHER_CTX *cipher);

    /// AES encryption - ke version
    /// @param[in] context Input context string
    /// @param[in] cipher  Encryption context
    static unsigned char *keAES(const std::string &context, EVP_CIPHER_CTX *cipher);

    /// AES encryption - kv version
    /// @param[in] context Input context string
    /// @param[in] cipher  Encryption context
    static unsigned char *kvAES(const std::string &context, EVP_CIPHER_CTX *cipher);

    /// AES encryption - kr version
    /// @param[in] context Input context string
    /// @param[in] cipher  Encryption context
    static unsigned char *krAES(const std::string &context, EVP_CIPHER_CTX *cipher);

    /// AES decryption
    /// @param[in] result       Encrypted data
    /// @param[in] result_len   Length of encrypted data
    /// @param[in] originalKey  Original encryption key
    static unsigned char *decrypt(unsigned char *result, size_t result_len, unsigned char *originalKey);
};

#endif // DGTOTP_PRF_H