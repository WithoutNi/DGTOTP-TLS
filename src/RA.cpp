#include "RA.h"
#include "Parameter.h"
#include "ChameleonHash.h"
#include "DGTOTP_PRF.h"
#include "MerkleTrees.h"
#include "TOTP.h"
#include "Member.h"
#include "util.h"
#include <cstring>
#include <cmath>
#include <ctime>
#include <algorithm>
#include <random>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <string>

void RA::RASetup(int security_parameter, std::string group_name, int group_member_count, long start_time, long end_time,
                 int verification_period, int password_generation_period)
{
    k = security_parameter;

    // Chameleon hash setup
    ChameleonHash chameleon;
    chameleon.init();

    // Parameter initialization
    G = group_name;
    U = group_member_count;
    START_TIME = start_time;
    END_TIME = end_time;
    E = (END_TIME - START_TIME) / verification_period;
    N = verification_period / password_generation_period;

    // Initialize data structures
    SMT.resize(E);
    merkle_proof.resize(E);
    per_table.resize(E);
    sub_tree.resize((int)ceil(log2(U)), std::vector<std::string>(U));
    ID_byte_cipher.resize(U);

    rk = (unsigned char *)malloc(byte_size);
    dvp = (unsigned char *)malloc(byte_size);
    rd = (unsigned char *)malloc(byte_size);

    ch_hash.resize(E, std::vector<int>(U));
    CH_hash.resize(E, std::vector<int>(U));

    // Revocation list
    RL = (unsigned char *)calloc(U, 1);

    // Registered group member identities
    IDLG.resize(U);

    // Generate RA key
    unsigned char *key = DGTOTP_PRF::createKey();

    // RA AES key cipher initialization
    ks_cipher = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ks_cipher);
    EVP_EncryptInit_ex(ks_cipher, EVP_aes_128_ecb(), nullptr, key, nullptr);

    // Initialize member ks
    unsigned char *Member_ks = nullptr;
    for (int j = 0; j < U; j++)
    {
        if (RL[j] == 1)
            continue; // Skip revoked members

        // Generate ks
        cache_tem = DGTOTP_PRF::ksAES(G + "KS" + std::to_string(j), ks_cipher);

        for (int i = 0; i < E; i++)
        {
            // Virtual verification point
            unsigned char *part1 = DGTOTP_PRF::jdkAES(G + "DVP" + std::to_string(i), cache_tem);
            unsigned char *part2 = DGTOTP_PRF::jdkAES(G + "DVP" + std::to_string(i), cache_tem);
            unsigned char *result = Parameter::byteMerger(part1, 16, part2, 16);
            memcpy(dvp, result, byte_size);
            free(part1);
            free(part2);
            free(result);

            // Random number
            part1 = DGTOTP_PRF::jdkAES(G + "DR" + std::to_string(i), cache_tem);
            part2 = DGTOTP_PRF::jdkAES(G + "DR" + std::to_string(i), cache_tem);
            result = Parameter::byteMerger(part1, 16, part2, 16);
            memcpy(rd, result, byte_size);
            free(part1);
            free(part2);
            free(result);

            // Generate chameleon hash key
            part1 = DGTOTP_PRF::jdkAES(G + "CHR" + std::to_string(i), cache_tem);
            part2 = DGTOTP_PRF::jdkAES(G + "CHR" + std::to_string(i), cache_tem);
            result = Parameter::byteMerger(part1, 16, part2, 16);
            memcpy(rk, result, byte_size);
            free(part1);
            free(part2);
            free(result);

            // Setup chameleon hash
            ChameleonHash ch;
            ch.Setup(rk);

            // Generate permuted merkle subtree nodes
            CH_hash[i][j] = ch.eval(dvp, byte_size, ch.getPk(), rd, byte_size);
        }

        free(cache_tem);
    }

    // Permute chameleon hash values
    for (int i = 0; i < E; i++)
    {
        // Generate permutation set
        cache_tem = DGTOTP_PRF::ksAES(G + "PM" + std::to_string(i), ks_cipher);
        unsigned int seed = 0;
        memcpy(&seed, cache_tem, sizeof(unsigned int));
        per_table[i] = Permutation(seed);
        free(cache_tem);

        // Permute chameleon hash values
        for (int j = 0; j < U; j++)
        {
            ch_hash[i][per_table[i][j]] = CH_hash[i][j];
        }

        // Generate E Merkle trees for chameleon hash values
        std::vector<std::string> ch_hash_str(U);
        for (int j = 0; j < U; j++)
        {
            ch_hash_str[j] = std::to_string(ch_hash[i][j]);
        }

        MerkleTrees merkle_tree(ch_hash_str);
        merkle_tree.merkle_tree();
        SMT[i] = merkle_tree.getRoot();
    }

    // Generate merkle proofs for tree containing subtree roots
    MerkleTrees root_tree_builder(SMT);
    std::vector<std::vector<std::string>> root_tree = root_tree_builder.get_tree(SMT);
    for (int i = 0; i < E; i++)
    {
        merkle_proof[i] = root_tree_builder.Get_Proof(root_tree, SMT[i], i);
    }

    // Group public key
    MerkleTrees merkle_tree(SMT);
    merkle_tree.merkle_tree();
    gpk = merkle_tree.getRoot();

    free(key);
}

unsigned char *RA::intToBytes(int i)
{
    unsigned char *bytes = (unsigned char *)malloc(4);
    bytes[0] = (unsigned char)(i & 0xff);
    bytes[1] = (unsigned char)((i >> 8) & 0xff);
    bytes[2] = (unsigned char)((i >> 16) & 0xff);
    bytes[3] = (unsigned char)((i >> 24) & 0xff);
    return bytes;
}

std::vector<int> RA::Permutation(unsigned int random_seed)
{
    std::vector<int> list(U);
    for (int i = 0; i < U; i++)
    {
        list[i] = i;
    }

    // Use random number generator
    std::mt19937 rng(random_seed);
    std::shuffle(list.begin(), list.end(), rng);
    return list;
}

void RA::GMUpdate(long time, Parameter &params)
{
    int instance_index = (int)((time - START_TIME) / params.getDeltaE());

    // V
    std::vector<int> V(U);
    std::vector<int> per_V(U);

    // Chameleon hash public keys
    std::vector<EC_POINT *> public_key(U, nullptr);
    std::vector<EC_POINT *> per_public_key(U, nullptr);

    EVP_CIPHER_CTX *ks = nullptr;
    unsigned char *dvp = (unsigned char *)malloc(byte_size);
    unsigned char *rd = (unsigned char *)malloc(byte_size);
    unsigned char *rk = (unsigned char *)malloc(byte_size);

    std::vector<std::string> ciphertext(U);
    std::vector<std::string> per_ciphertext(U);

    // Compute U member identity ciphertexts
    for (int i = 0; i < U; i++)
    {
        cache_tem = DGTOTP_PRF::ksAES(G + "KS" + std::to_string(i), ks_cipher);

        // Virtual vp
        unsigned char *part1 = DGTOTP_PRF::jdkAES(G + "DVP" + std::to_string(instance_index), cache_tem);
        unsigned char *part2 = DGTOTP_PRF::jdkAES(G + "DVP" + std::to_string(instance_index), cache_tem);
        unsigned char *result = Parameter::byteMerger(part1, 16, part2, 16);
        memcpy(dvp, result, byte_size);
        free(part1);
        free(part2);
        free(result);

        part1 = DGTOTP_PRF::jdkAES(G + "DR" + std::to_string(instance_index), cache_tem);
        part2 = DGTOTP_PRF::jdkAES(G + "DR" + std::to_string(instance_index), cache_tem);
        result = Parameter::byteMerger(part1, 16, part2, 16);
        memcpy(rd, result, byte_size);
        free(part1);
        free(part2);
        free(result);

        part1 = DGTOTP_PRF::jdkAES(G + "CHR" + std::to_string(instance_index), cache_tem);
        part2 = DGTOTP_PRF::jdkAES(G + "CHR" + std::to_string(instance_index), cache_tem);
        result = Parameter::byteMerger(part1, 16, part2, 16);
        memcpy(rk, result, byte_size);
        free(part1);
        free(part2);
        free(result);

        // Chameleon hash setup
        params.getChameHash()->Setup(rk);
        public_key[i] = params.getChameHash()->clonePublicKey();

        // Chameleon hash eval
        V[i] = params.getChameHash()->eval(dvp, byte_size, public_key[i], rd, byte_size);

        // Compute ID ciphertext
        unsigned char *ke = DGTOTP_PRF::jdkAES("KeyGen" + std::to_string(instance_index), cache_tem);
        unsigned char *re = DGTOTP_PRF::jdkAES("Rand" + std::to_string(instance_index), cache_tem);

        // Error handling
        if (!ke || !re)
        {
            printf("ke or re is null!!\n");
            free(ke);
            free(re);
            free(cache_tem);
            continue;
        }

        // ASEe
        unsigned char *id_bytes = intToBytes(i);
        if (!id_bytes)
        {
            printf("intToBytes failed for member %d\n", i);
            free(ke);
            free(re);
            free(cache_tem);
            continue;
        }
        unsigned char *cipher = ASE_enc(id_bytes, 4, ke, re, params.getNonce());

        if (!cipher)
        {
            printf("ASE_enc failed for member %d\n", i);
            free(id_bytes);
            free(ke);
            free(re);
            free(cache_tem);
            continue;
        }
        ciphertext[i] = std::string(reinterpret_cast<char *>(cipher), 20);

        free(ke);
        free(re);
        free(id_bytes);
        free(cipher);
        free(cache_tem);
    }

    // Permutation
    cache_tem = DGTOTP_PRF::ksAES(G + "PM" + std::to_string(instance_index), ks_cipher);
    unsigned int seed = 0;
    memcpy(&seed, cache_tem, sizeof(unsigned int));
    per_table[instance_index] = Permutation(seed);

    for (int i = 0; i < U; i++)
    {
        const int permuted_index = per_table[instance_index][i];
        per_V[permuted_index] = V[i];
        per_ciphertext[permuted_index] = ciphertext[i];
        per_public_key[permuted_index] = public_key[i];
    }

    // Publish group management message
    std::vector<std::string> proof = merkle_proof[instance_index];

    // Proof length
    params.setProofLen(proof.size());

    // Subtree root proof
    params.setMerkleProof(proof);

    // Subtree nodes
    params.setChHash(per_V);

    // ID ciphertexts
    params.setMemberCipher(per_ciphertext);

    // Chameleon hash public keys
    params.setChKey(per_public_key);

    // Group public key
    params.setGpk(gpk);

    MerkleTrees verifier_tree(SMT);
    verifier_tree.Verify(params.getMerkleProof(), SMT[instance_index], SMT[instance_index], instance_index);

    // Clean up resources
    free(dvp);
    free(rd);
    free(rk);
}

std::string RA::Open(const std::vector<std::string> &password, long time, Parameter &params)
{
    // Get permuted MPI Id index
    per_id_index = 0;
    for (int j = 0; j < U; j++)
    {
        if (params.getMemberCipher()[j] == password[2])
        {
            per_id_index = j;
            break;
        }
    }

    verify_epoch = (int)((time - START_TIME) / params.getDeltaE());
    current_verify_epoch = (int)((std::time(nullptr) * 1000 - params.getStartTime()) / params.getDeltaE());

    if (verify_epoch != current_verify_epoch)
    {
        return "";
    }

    long pw_sequence = (time - verify_epoch * params.getDeltaE() - START_TIME) / params.getDeltaS();

    // Get TOTP verification point (byte array)
    unsigned char *cache_tem = static_cast<unsigned char *>(malloc(32));
    memcpy(cache_tem, password[0].data(), 32);

    for (int i = 0; i < pw_sequence + 1; i++)
    {
        unsigned char *temp = Parameter::Sha256(cache_tem, 32);
        memcpy(cache_tem, temp, 32);
        free(temp);
    }

    // TOTP verification point
    std::string vp(reinterpret_cast<char *>(cache_tem), 32);
    std::string vp_hex = Member::byte2hex(cache_tem, 32);
    free(cache_tem);

    unsigned char *vp_bytes = Parameter::Sha256(vp_hex + password[2] + std::to_string(verify_epoch));

    // "ISO-8859-1" string -> byte array chameleon hash eval
    int vp_point = params.getChameHash()->eval(vp_bytes, 32,
                                               params.getChKey()[per_id_index],
                                               (unsigned char *)password[1].c_str(), password[1].length());

    // Permutation
    cache_tem = DGTOTP_PRF::ksAES(G + "PM" + std::to_string(verify_epoch), ks_cipher);
    unsigned int seed = 0;
    memcpy(&seed, cache_tem, sizeof(unsigned int));
    std::vector<int> regen_per_table = Permutation(seed);
    free(cache_tem);

    int original_member_index = -1;
    for (int i = 0; i < U; i++)
    {
        if (regen_per_table[i] == per_id_index)
        {
            original_member_index = i;
            break;
        }
    }

    if (original_member_index == -1 || vp_point != params.getChHash()[per_id_index])
    {
        free(vp_bytes);
        return "";
    }

    // TOTP.verify && Merkle.verify
    TOTP totp;
    totp.Setup(params);
    MerkleTrees verifier_tree(SMT);
    if (verifier_tree.Verify(params.getMerkleProof(), SMT[verify_epoch], params.getGpk(), verify_epoch) == 1 &&
        totp.Verify(vp, password[0], pw_sequence) == 1)
    {

        cache_tem = DGTOTP_PRF::ksAES(G + "KS" + std::to_string(original_member_index), ks_cipher);

        unsigned char *ke = DGTOTP_PRF::jdkAES("KeyGen" + std::to_string(verify_epoch), cache_tem);
        unsigned char *re = DGTOTP_PRF::jdkAES("Rand" + std::to_string(verify_epoch), cache_tem);

        // Decrypt identity ciphertext
        unsigned char *id_bytes = ASE_dec(ke, (unsigned char *)params.getMemberCipher()[per_id_index].c_str(), params.getMemberCipher()[per_id_index].length(), re, params.getNonce());

        int ID_plain = Parameter::bytesToInt(id_bytes);

        free(cache_tem);
        free(ke);
        free(re);
        free(id_bytes);
        free(vp_bytes);

        return IDLG[ID_plain];
    }
    free(vp_bytes);

    return "";
}

unsigned char *RA::ASE_enc(unsigned char *data, size_t data_len,
                           unsigned char *key, unsigned char *assocData, unsigned char *nonce)
{
    // Add stricter validation
    if (!data || !key || !assocData)
    {
        std::cerr << "ASE_enc: Invalid input parameters (null pointer)" << std::endl;
        return nullptr;
    }

    // Ensure key length is sufficient
    if (EVP_CIPHER_key_length(EVP_aes_128_gcm()) > 16)
    {
        std::cerr << "ASE_enc: Key length insufficient" << std::endl;
        return nullptr;
    }
    // Initialize encryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    // Set GCM mode
    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, key, nonce);

    int outlen;
    unsigned char *buf = (unsigned char *)malloc(16 + EVP_MAX_BLOCK_LENGTH);

    // Set associated data
    EVP_EncryptUpdate(ctx, buf, &outlen, assocData, 16);

    // Encrypt data
    int outlen1, outlen2;
    unsigned char *outbuf = (unsigned char *)malloc(data_len + EVP_MAX_BLOCK_LENGTH);

    EVP_EncryptUpdate(ctx, outbuf, &outlen1, data, data_len);
    EVP_EncryptFinal_ex(ctx, outbuf + outlen1, &outlen2);

    // Get authentication tag
    unsigned char tag[16];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);

    // Combine ciphertext and tag
    unsigned char *result = (unsigned char *)malloc(outlen1 + outlen2 + 16);
    memcpy(result, outbuf, outlen1 + outlen2);
    memcpy(result + outlen1 + outlen2, tag, 16);

    // Clean up resources
    free(buf);
    free(outbuf);
    EVP_CIPHER_CTX_free(ctx);

    return result;
}

unsigned char *RA::ASE_dec(unsigned char *key, unsigned char *data,
                           size_t data_len, unsigned char *assocData, unsigned char *nonce)
{
    // Add stricter validation
    if (!data || !key || !assocData)
    {
        std::cerr << "ASE_enc: Invalid input parameters (null pointer)" << std::endl;
        return nullptr;
    }

    // Ensure key length is sufficient
    if (EVP_CIPHER_key_length(EVP_aes_128_gcm()) > 16)
    {
        std::cerr << "ASE_enc: Key length insufficient" << std::endl;
        return nullptr;
    }
    // Initialize decryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(ctx);

    // Set GCM mode
    EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, key, nonce);

    int outlen;
    unsigned char *buf = (unsigned char *)malloc(16 + EVP_MAX_BLOCK_LENGTH);

    // Set associated data
    EVP_DecryptUpdate(ctx, buf, &outlen, assocData, 16);

    // Separate ciphertext and tag
    unsigned char *ciphertext = (unsigned char *)malloc(data_len - 16);
    unsigned char tag[16];

    memcpy(ciphertext, data, data_len - 16);
    memcpy(tag, data + data_len - 16, 16);

    // Set authentication tag
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);

    // Decrypt data
    int outlen1, outlen2;
    unsigned char *outbuf = (unsigned char *)malloc(data_len);

    EVP_DecryptUpdate(ctx, outbuf, &outlen1, ciphertext, data_len - 16);
    EVP_DecryptFinal_ex(ctx, outbuf + outlen1, &outlen2);

    // Adjust output size
    unsigned char *result = (unsigned char *)malloc(outlen1 + outlen2);
    memcpy(result, outbuf, outlen1 + outlen2);

    // Clean up resources
    free(buf);
    free(outbuf);
    free(ciphertext);
    EVP_CIPHER_CTX_free(ctx);

    return result;
}

std::vector<unsigned char *> RA::Join(EVP_CIPHER_CTX *ks, const std::string &ID, long time)
{
    std::vector<unsigned char *> Ax(2);

    // Ks byte array
    IDLG[alpha] = ID;
    Ax[0] = DGTOTP_PRF::ksAES(G + "KS" + std::to_string(alpha), ks_cipher);

    // alpha ID index byte array
    Ax[1] = intToBytes(alpha);
    alpha++;

    return Ax;
}

bool RA::IsJoinedMember(const std::string &memberId) const
{
    return std::find(IDLG.begin(), IDLG.end(), memberId) != IDLG.end();
}

int RA::Revoke(const std::string &ID, EVP_CIPHER_CTX *RA_key)
{
    per_id_index = 0;
    int result = 0;

    for (int i = 0; i < IDLG.size(); i++)
    {
        if (IDLG[i] == ID)
        {
            per_id_index = i;
            result = 1;
            break;
        }
    }

    RL[per_id_index] = 1;

    return result;
}

void RA::cleanup()
{
    // Free all dynamically allocated memory
    if (rk)
        free(rk);
    if (dvp)
        free(dvp);
    if (rd)
        free(rd);
    if (RL)
        free(RL);

    // Clean OpenSSL contexts
    if (Key_RA)
    {
        EVP_CIPHER_CTX_free(Key_RA);
        Key_RA = nullptr;
    }
    if (ks_cipher)
    {
        EVP_CIPHER_CTX_free(ks_cipher);
        ks_cipher = nullptr;
    }

    // Clear containers
    SMT.clear();
    merkle_proof.clear();
    per_table.clear();
    sub_tree.clear();
    IDLG.clear();
    ID_byte_cipher.clear();
}
