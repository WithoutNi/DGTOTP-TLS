#ifndef KEYGEN_H
#define KEYGEN_H

#include <string>
#include <openssl/evp.h>
#include <openssl/x509.h>

/// Default subject string for certificates
#define DEFAULT_SUBJECT "/C=CN/ST=Beijing/L=Beijing/O=DGTOTP-TLS/CN=localhost"

/// Default CA certificate and key filenames
#define DEFAULT_CA_CERT "ca.crt"
#define DEFAULT_CA_KEY "ca.key"

/// Default validity period in days
#define DEFAULT_DAYS_VALID 365

/// Default curve for EC key generation
#define DEFAULT_EC_CURVE NID_X9_62_prime256v1

/// Generate EC key pair (prime256v1)
/// @param[out] pkey: Output parameter for the generated key
/// @return: true on success, false on failure
bool generateECKey(EVP_PKEY **pkey);

/// Save private key to PEM file
/// @param[in] pkey: The private key to save
/// @param[in] filename: Output filename
/// @return: true on success, false on failure
bool savePrivateKeyToFile(EVP_PKEY *pkey, const std::string &filename);

/// Check if a file exists
/// @param[in] filename: File to check
/// @return: true if file exists, false otherwise
bool fileExists(const std::string &filename);

/// Load private key from PEM file
/// @param[in] filename: Input filename
/// @param[out] pkey: Output parameter for the loaded key
/// @return: true on success, false on failure
bool loadPrivateKey(const std::string &filename, EVP_PKEY **pkey);

/// Load certificate from PEM file
/// @param[in] filename: Input filename
/// @param[out] cert: Output parameter for the loaded certificate
/// @return: true on success, false on failure
bool loadCertificate(const std::string &filename, X509 **cert);

/// Load CA private key from PEM file
/// @param[in] filename: Input filename
/// @param[out] pkey: Output parameter for the loaded key
/// @return: true on success, false on failure
bool loadPrivateKeyCA(const std::string &filename, EVP_PKEY **pkey);

/// Sign certificate using CA (no CSR file needed)
/// @param[in] pkey: The private key to be signed into certificate
/// @param[out] cert_filename: Output certificate filename
/// @param[in] ca_cert_filename: CA certificate filename (default: "ca.crt")
/// @param[in] ca_key_filename: CA private key filename (default: "ca.key")
/// @param[in] subject: X.509 subject string (default: "/C=CN/ST=Beijing/L=Beijing/O=DGTOTP-TLS/CN=localhost")
/// @param[in] days_valid: Validity period in days (default: 365)
/// @return: true on success, false on failure
bool signCertificate(EVP_PKEY *pkey,
                     const std::string &cert_filename,
                     const std::string &ca_cert_filename = DEFAULT_CA_CERT,
                     const std::string &ca_key_filename = DEFAULT_CA_KEY,
                     const std::string &subject = DEFAULT_SUBJECT,
                     int days_valid = DEFAULT_DAYS_VALID);

/// Generate key and certificate
/// @param[out] key_filename: Output private key filename
/// @param[out] cert_filename: Output certificate filename
/// @param[in] ca_cert_filename: CA certificate filename (default: "ca.crt")
/// @param[in] ca_key_filename: CA private key filename (default: "ca.key")
/// @param[in] subject: X.509 subject string (default: "/C=CN/ST=Beijing/L=Beijing/O=DGTOTP-TLS/CN=localhost")
/// @param[in] days_valid: Validity period in days (default: 365)
/// @return: true on success, false on failure
bool GenerateKeyAndCertificate(const std::string &key_filename,
                               const std::string &cert_filename,
                               const std::string &ca_cert_filename = DEFAULT_CA_CERT,
                               const std::string &ca_key_filename = DEFAULT_CA_KEY,
                               const std::string &subject = DEFAULT_SUBJECT,
                               int days_valid = DEFAULT_DAYS_VALID);

#endif /// KEYGEN_H