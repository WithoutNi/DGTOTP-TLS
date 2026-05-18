#ifndef RA_H
#define RA_H

#include <string>
#include <vector>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <cmath>

// Forward declaration
class Parameter;

/**
 * RA class - Registration Authority functionality
 */
class RA
{
public:
    RA() = default;

    /// Initialize Registration Authority setup
    /// @param[in] security_parameter        Security parameter
    /// @param[in] group                     Group instance identifier or representation
    /// @param[in] group_member_count        Number of group members
    /// @param[in] start_time                Start time (timestamp)
    /// @param[in] end_time                  End time (timestamp)
    /// @param[in] verification_period       Verification period (delta_e)
    /// @param[in] password_generation_period Password generation period (delta_s)
    void RASetup(int security_parameter, std::string group_name, int group_member_count, long start_time, long end_time,
                 int verification_period, int password_generation_period);

    /// Generate permutation sequence
    /// @param[in] random_seed Random number generator seed
    /// @return Permutation sequence
    std::vector<int> Permutation(unsigned int random_seed);

    /// Update group management message
    /// @param[in] time Current time
    /// @param[in] params Parameter instance
    void GMUpdate(long time, Parameter &params);

    /// Open member identity
    /// @param[in] password Password array
    /// @param[in] time     Current time
    /// @param[in] params Parameter instance
    /// @return Member ID if successful, empty string otherwise
    std::string Open(const std::vector<std::string> &password, long time, Parameter &params);

    /// Process member join request
    /// @param[in] ks   Key context
    /// @param[in] ID   Member identifier
    /// @param[in] time Current time
    /// @return Parameter array for member setup
    std::vector<unsigned char *> Join(EVP_CIPHER_CTX *ks, const std::string &ID, long time);

    /// Check whether a member identifier has already been registered
    /// @param[in] memberId Member identifier
    /// @return true if the identifier already exists in IDLG, false otherwise
    bool IsJoinedMember(const std::string &memberId) const;

    /// Revoke member from group
    /// @param[in] ID      Member identifier
    /// @param[in] RA_key  RA key context
    /// @return 1 if successful, 0 if member not found
    int Revoke(const std::string &ID, EVP_CIPHER_CTX *RA_key);

    /// Clean up allocated resources
    void cleanup();

    /// Convert integer to byte array
    /// @param[in] i Integer value
    /// @return Byte array
    static unsigned char *intToBytes(int i);

    /// AES-GCM encryption
    /// @param[in] data       Plaintext data
    /// @param[in] data_len   Data length
    /// @param[in] key        Encryption key
    /// @param[in] assocData  Associated authentication data
    /// @param[in] nonce      AES-GCM noonce
    /// @return Encrypted ciphertext with authentication tag
    static unsigned char *ASE_enc(unsigned char *data, size_t data_len,
                                  unsigned char *key, unsigned char *assocData, unsigned char *nonce);

    /// AES-GCM decryption
    /// @param[in] key        Decryption key
    /// @param[in] data       Ciphertext data
    /// @param[in] data_len   Data length
    /// @param[in] assocData  Associated authentication data
    /// @param[in] nonce      AES-GCM noonce
    /// @return Decrypted plaintext
    static unsigned char *ASE_dec(unsigned char *key, unsigned char *data,
                                  size_t data_len, unsigned char *assocData, unsigned char *nonce);

    int getU() const { return U; }
    int getJoinedMemberCount() const { return alpha; }
    const std::vector<std::string> &getIDLG() const { return IDLG; }
    const std::string &getGpk() const { return gpk; }
    const std::vector<std::string> &getSMT() const { return SMT; }
    EVP_CIPHER_CTX *getKsCipher() const { return ks_cipher; }

private:
    /// Number of group members
    int U = 0;

    /// Security parameter
    int k = 0;

    /// Number of passwords in TOTP instance
    int N = 0;

    /// Number of TOTP protocol instances
    int E = 0;

    /// Start time (timestamp)
    long START_TIME = 0;

    /// End time (timestamp)
    long END_TIME = 0;

    /// Permutation key bytes
    unsigned char *KEY_PERMUTATION = nullptr;

    /// RA's key context
    EVP_CIPHER_CTX *Key_RA = nullptr;

    /// Merkle tree root proof (per member)
    std::vector<std::vector<std::string>> merkle_proof;

    /// Chameleon hash values
    std::vector<std::vector<int>> CH_hash;

    /// Permuted chameleon hash values
    std::vector<std::vector<int>> ch_hash;

    /// Virtual verification point bytes
    unsigned char *dvp = nullptr;

    /// Random number bytes
    unsigned char *rd = nullptr;

    /// Sub Merkle tree (SMT) strings
    std::vector<std::string> SMT;

    /// Group public key
    std::string gpk;

    /// E permutation table
    std::vector<std::vector<int>> per_table;

    /// Merkle tree subtrees
    std::vector<std::vector<std::string>> sub_tree;

    /// Chameleon hash secret key bytes
    unsigned char *rk = nullptr;

    /// Identities of registered group members
    std::vector<std::string> IDLG;

    /// Revocation list bytes
    unsigned char *RL = nullptr;

    /// Specific verification epoch
    int verify_epoch = 0;

    /// Cached permuted id index
    int per_id_index = 0;

    /// Byte size (e.g., 32 bytes)
    int byte_size = 32;

    /// Index for member joining
    int alpha = 0;

    /// Temporary cache bytes
    unsigned char *cache_tem = nullptr;

    /// Member ID ciphertexts (per member, per field)
    std::vector<std::vector<unsigned char *>> ID_byte_cipher;

    /// RA key ciphertext context
    EVP_CIPHER_CTX *ks_cipher = nullptr;

    /// Group instance identifier or representation
    std::string G;

    /// Current verification period
    int current_verify_epoch = 0;
};

#endif // RA_H
