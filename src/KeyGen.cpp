#include "KeyGen.h"

#include <iostream>
#include <cstring>
#include <sys/stat.h>

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/bio.h>

// ============================================================
// Helper functions for extractKeyPair
// ============================================================

static bool writeKeyToBio(EVP_PKEY *pkey, BIO *bio, bool is_private)
{
    if (is_private)
    {
        return PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr) > 0;
    }
    else
    {
        return PEM_write_bio_PUBKEY(bio, pkey) > 0;
    }
}

static std::string bioToString(BIO *bio)
{
    char *data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    if (len > 0 && data)
    {
        return std::string(data, len);
    }
    return "";
}

// ============================================================
// EC Key Generation
// ============================================================

bool generateECKey(EVP_PKEY **pkey)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!ctx)
        return false;

    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, DEFAULT_EC_CURVE) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    if (EVP_PKEY_keygen(ctx, pkey) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    EVP_PKEY_CTX_free(ctx);
    return true;
}

bool savePrivateKeyToFile(EVP_PKEY *pkey, const std::string &filename)
{
    BIO *bio = BIO_new_file(filename.c_str(), "w");
    if (!bio)
        return false;

    bool result = PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr) > 0;
    BIO_free(bio);
    return result;
}

// ============================================================
// Key Pair Extraction
// ============================================================

bool extractKeyPair(EVP_PKEY *pkey, std::string &pk, std::string &sk)
{
    if (!pkey)
    {
        return false;
    }

    // Check if it's an EC key
    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_EC)
    {
        return false;
    }

    // Extract private key (SK)
    BIO *sk_bio = BIO_new(BIO_s_mem());
    if (!sk_bio)
    {
        return false;
    }

    if (!writeKeyToBio(pkey, sk_bio, true))
    {
        BIO_free(sk_bio);
        return false;
    }

    sk = bioToString(sk_bio);
    BIO_free(sk_bio);

    if (sk.empty())
    {
        return false;
    }

    // Extract public key (PK)
    BIO *pk_bio = BIO_new(BIO_s_mem());
    if (!pk_bio)
    {
        return false;
    }

    if (!writeKeyToBio(pkey, pk_bio, false))
    {
        BIO_free(pk_bio);
        return false;
    }

    pk = bioToString(pk_bio);
    BIO_free(pk_bio);

    if (pk.empty())
    {
        return false;
    }

    return true;
}

bool KeyGen(std::string &pk, std::string &sk)
{
    EVP_PKEY *pkey = nullptr;

    if (!generateECKey(&pkey))
    {
        std::cerr << "KeyGen: Failed to generate EC key" << std::endl;
        return false;
    }

    bool result = extractKeyPair(pkey, pk, sk);
    EVP_PKEY_free(pkey);

    if (!result)
    {
        std::cerr << "KeyGen: Failed to extract key pair" << std::endl;
        return false;
    }

    return true;
}

// ============================================================
// File Operations
// ============================================================

bool fileExists(const std::string &filename)
{
    struct stat buffer;
    return (stat(filename.c_str(), &buffer) == 0);
}

bool loadPrivateKey(const std::string &filename, EVP_PKEY **pkey)
{
    BIO *bio = BIO_new_file(filename.c_str(), "r");
    if (!bio)
        return false;

    *pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return (*pkey != nullptr);
}

bool loadCertificate(const std::string &filename, X509 **cert)
{
    BIO *bio = BIO_new_file(filename.c_str(), "r");
    if (!bio)
        return false;

    *cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return (*cert != nullptr);
}

// ============================================================
// Certificate Signing
// ============================================================

bool signCertificate(EVP_PKEY *pkey,
                     const std::string &cert_filename,
                     const std::string &ca_cert_filename,
                     const std::string &ca_key_filename,
                     const std::string &subject,
                     int days_valid)
{
    // Load CA certificate
    X509 *ca_cert = nullptr;
    if (!loadCertificate(ca_cert_filename, &ca_cert))
    {
        std::cerr << "Failed to load CA certificate: " << ca_cert_filename << std::endl;
        return false;
    }

    // Load CA private key
    EVP_PKEY *ca_pkey = nullptr;
    if (!loadPrivateKey(ca_key_filename, &ca_pkey))
    {
        std::cerr << "Failed to load CA private key: " << ca_key_filename << std::endl;
        X509_free(ca_cert);
        return false;
    }

    // Create new certificate
    X509 *cert = X509_new();
    if (!cert)
    {
        X509_free(ca_cert);
        EVP_PKEY_free(ca_pkey);
        return false;
    }

    // Set version (v3)
    X509_set_version(cert, 2);

    // Set serial number (random)
    ASN1_INTEGER *serial = ASN1_INTEGER_new();
    BIGNUM *bn_serial = BN_new();
    BN_rand(bn_serial, 128, 0, 0);
    BN_to_ASN1_INTEGER(bn_serial, serial);
    BN_free(bn_serial);
    X509_set_serialNumber(cert, serial);
    ASN1_INTEGER_free(serial);

    // Set validity period
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), days_valid * 24 * 60 * 60);

    // Set public key
    X509_set_pubkey(cert, pkey);

    // Set subject name
    X509_NAME *name = X509_NAME_new();
    if (!name)
    {
        X509_free(cert);
        X509_free(ca_cert);
        EVP_PKEY_free(ca_pkey);
        return false;
    }

    // Parse subject string
    std::string subj = subject;
    size_t pos = 0;
    while ((pos = subj.find('/')) != std::string::npos)
    {
        subj.erase(0, pos + 1);
        size_t end = subj.find('/');
        std::string entry = (end == std::string::npos) ? subj : subj.substr(0, end);
        size_t eq = entry.find('=');
        if (eq != std::string::npos)
        {
            std::string key = entry.substr(0, eq);
            std::string value = entry.substr(eq + 1);
            X509_NAME_add_entry_by_txt(name, key.c_str(), MBSTRING_ASC,
                                       (const unsigned char *)value.c_str(), -1, -1, 0);
        }
        if (end == std::string::npos)
            break;
        subj.erase(0, end);
    }

    X509_set_subject_name(cert, name);
    X509_NAME_free(name);

    // Set issuer name from CA certificate
    X509_set_issuer_name(cert, X509_get_subject_name(ca_cert));

    // Add subjectAltName extension
    X509V3_CTX ext_ctx;
    X509V3_set_ctx(&ext_ctx, ca_cert, cert, nullptr, nullptr, 0);

    X509_EXTENSION *san_ext = X509V3_EXT_conf(nullptr, &ext_ctx,
                                              (char *)"subjectAltName",
                                              (char *)"DNS:localhost,IP:127.0.0.1");

    if (san_ext)
    {
        X509_add_ext(cert, san_ext, -1);
        X509_EXTENSION_free(san_ext);
    }

    // Sign certificate with CA private key
    if (X509_sign(cert, ca_pkey, EVP_sha256()) <= 0)
    {
        std::cerr << "Failed to sign certificate" << std::endl;
        X509_free(cert);
        X509_free(ca_cert);
        EVP_PKEY_free(ca_pkey);
        return false;
    }

    // Write certificate to file
    BIO *cert_bio = BIO_new_file(cert_filename.c_str(), "w");
    if (!cert_bio)
    {
        X509_free(cert);
        X509_free(ca_cert);
        EVP_PKEY_free(ca_pkey);
        return false;
    }

    bool result = PEM_write_bio_X509(cert_bio, cert) > 0;
    BIO_free(cert_bio);

    // Cleanup
    X509_free(cert);
    X509_free(ca_cert);
    EVP_PKEY_free(ca_pkey);

    return result;
}

// ============================================================
// Combined Function
// ============================================================

bool GenerateKeyAndCertificate(const std::string &key_filename,
                               const std::string &cert_filename,
                               const std::string &ca_cert_filename,
                               const std::string &ca_key_filename,
                               const std::string &subject,
                               int days_valid)
{
    // Step 1: Generate EC key
    EVP_PKEY *pkey = nullptr;
    if (!generateECKey(&pkey))
    {
        std::cerr << "Failed to generate EC key" << std::endl;
        return false;
    }

    // Step 2: Save private key
    if (!savePrivateKeyToFile(pkey, key_filename))
    {
        std::cerr << "Failed to save private key: " << key_filename << std::endl;
        EVP_PKEY_free(pkey);
        return false;
    }

    // Step 3: Sign certificate directly (no CSR file needed)
    if (!signCertificate(pkey, cert_filename, ca_cert_filename, ca_key_filename, subject, days_valid))
    {
        std::cerr << "Failed to sign certificate: " << cert_filename << std::endl;
        EVP_PKEY_free(pkey);
        return false;
    }

    EVP_PKEY_free(pkey);
    return true;
}