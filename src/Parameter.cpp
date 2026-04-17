#include "Parameter.h"
#include "ChameleonHash.h"
#include <cstring>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <ctime>

// Constructor
Parameter::Parameter()
    : U(0), k(128), N(60), E(0), START_TIME(0), END_TIME(0), Δe(300000), Δs(5000),
      chame_hash(nullptr), digest(nullptr), G(""), AesCipher(nullptr), nonce(nullptr),
      proof_len(0), gpk("")
{
    // Initialize vectors with default sizes
    CH_hash.resize(U);
    Member_cipher.resize(U);
    CH_key.resize(U);
    merkle_proof.resize(proof_len);
}

// Destructor
Parameter::~Parameter()
{
}

void Parameter::init(const std::string &groupId)
{
    init(groupId, time(nullptr) * 1000);
}

void Parameter::init(const std::string &groupId, long startTimestamp)
{
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();

    G = groupId;

    // Initialize chameleon hash
    chame_hash = new ChameleonHash();
    chame_hash->init();

    E = 2;
    U = 4;

    // Use the caller-provided shared start time
    START_TIME = startTimestamp;
    END_TIME = START_TIME + E * Δe;
    N = 60;

    // Initialize SHA256 context
    digest = EVP_MD_CTX_new();

    // Resize vectors based on new U value
    Member_cipher.resize(U);
    CH_key.resize(U);
    CH_hash.resize(U);
    merkle_proof.resize(proof_len);

    // Initialize nonce
    nonce = (unsigned char *)malloc(12);
    const char *nonce_str = "202122232425262728292a2b2c";
    for (int i = 0; i < 12; i++)
    {
        sscanf(&nonce_str[i * 2], "%2hhx", &nonce[i]);
    }

    // Initialize AES encryption context
    AesCipher = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(AesCipher);
}

unsigned char *Parameter::Sha256(unsigned char *message, size_t length)
{
    unsigned char *sha256Bytes = (unsigned char *)malloc(32);
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

    EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(mdctx, message, length);
    EVP_DigestFinal_ex(mdctx, sha256Bytes, nullptr);

    EVP_MD_CTX_free(mdctx);
    return sha256Bytes;
}

unsigned char *Parameter::Sha256(const std::string &message)
{
    return Sha256((unsigned char *)message.c_str(), message.length());
}

int Parameter::bytesToInt(unsigned char *bytes)
{
    if (!bytes)
    {
        return -1;
    }
    int i;
    i = (int)((bytes[0] & 0xff) | ((bytes[1] & 0xff) << 8) |
              ((bytes[2] & 0xff) << 16) | ((bytes[3] & 0xff) << 24));
    return i;
}

unsigned char *Parameter::byteMerger(unsigned char *byte_1, size_t byte_1_len,
                                     unsigned char *byte_2, size_t byte_2_len)
{
    unsigned char *byte_3 = (unsigned char *)malloc(byte_1_len + byte_2_len);
    memcpy(byte_3, byte_1, byte_1_len);
    memcpy(byte_3 + byte_1_len, byte_2, byte_2_len);
    return byte_3;
}

unsigned char *Parameter::intToBytes(int i)
{
    unsigned char *bytes = (unsigned char *)malloc(4);
    bytes[0] = (unsigned char)(i & 0xff);
    bytes[1] = (unsigned char)((i >> 8) & 0xff);
    bytes[2] = (unsigned char)((i >> 16) & 0xff);
    bytes[3] = (unsigned char)((i >> 24) & 0xff);
    return bytes;
}

void Parameter::cleanup()
{
    // Clean up chameleon hash keys
    for (int i = 0; i < U; i++)
    {
        if (CH_key[i] != nullptr)
        {
            EC_POINT_free(CH_key[i]);
            CH_key[i] = nullptr;
        }
    }

    // Clean up chameleon hash instance
    if (chame_hash != nullptr)
    {
        chame_hash->cleanup();
        delete chame_hash;
        chame_hash = nullptr;
    }

    // Clean up digest context
    if (digest != nullptr)
    {
        EVP_MD_CTX_free(digest);
        digest = nullptr;
    }

    // Clean up AES cipher context
    if (AesCipher != nullptr)
    {
        EVP_CIPHER_CTX_free(AesCipher);
        AesCipher = nullptr;
    }

    // Clean up nonce
    if (nonce != nullptr)
    {
        free(nonce);
        nonce = nullptr;
    }

    // Clear vectors
    CH_hash.clear();
    Member_cipher.clear();
    CH_key.clear();
    merkle_proof.clear();
}

// ===================== Setter Methods =====================

void Parameter::setU(int memberNum)
{
    U = memberNum;
    // Resize vectors when U changes
    CH_hash.resize(U);
    Member_cipher.resize(U);
    CH_key.resize(U);
}

void Parameter::setK(int securityParameter)
{
    k = securityParameter;
}

void Parameter::setN(int pwNum)
{
    N = pwNum;
}

void Parameter::setE(int totpNum)
{
    E = totpNum;
}

void Parameter::setStartTime(long startTimestamp)
{
    START_TIME = startTimestamp;
}

void Parameter::setEndTime(long endTimestamp)
{
    END_TIME = endTimestamp;
}

void Parameter::setDeltaE(int verificationPeriod)
{
    Δe = verificationPeriod;
}

void Parameter::setDeltaS(int generationPeriod)
{
    Δs = generationPeriod;
}

void Parameter::setChameHash(ChameleonHash *chameleon)
{
    if (chame_hash != nullptr)
    {
        chame_hash->cleanup();
        delete chame_hash;
    }
    chame_hash = chameleon;
}

void Parameter::setDigest(EVP_MD_CTX *digestContext)
{
    if (digest != nullptr)
    {
        EVP_MD_CTX_free(digest);
    }
    digest = digestContext;
}

void Parameter::setG(const std::string &groupName)
{
    G = groupName;
}

void Parameter::setAesCipher(EVP_CIPHER_CTX *aesContext)
{
    if (AesCipher != nullptr)
    {
        EVP_CIPHER_CTX_free(AesCipher);
    }
    AesCipher = aesContext;
}

void Parameter::setNonce(unsigned char *nonceValue)
{
    if (nonce != nullptr)
    {
        free(nonce);
    }
    nonce = nonceValue;
}

void Parameter::setChHash(const std::vector<int> &chamelonValues)
{
    CH_hash = chamelonValues;
}

void Parameter::setMemberCipher(const std::vector<std::string> &memberCiphertexts)
{
    Member_cipher = memberCiphertexts;
}

void Parameter::setChKey(const std::vector<EC_POINT *> &chamelonPKVec)
{
    // Clean up existing keys
    for (auto key : CH_key)
    {
        if (key != nullptr)
        {
            EC_POINT_free(key);
        }
    }
    CH_key = chamelonPKVec;
}

void Parameter::setMerkleProof(const std::vector<std::string> &merklrProofsVec)
{
    merkle_proof = merklrProofsVec;
}

void Parameter::setProofLen(int proofLength)
{
    proof_len = proofLength;
    merkle_proof.resize(proof_len);
}

void Parameter::setGpk(const std::string &groupPublicKey)
{
    gpk = groupPublicKey;
}

// ===================== Getter Methods =====================

int Parameter::getU() const
{
    return U;
}

int Parameter::getK() const
{
    return k;
}

int Parameter::getN() const
{
    return N;
}

int Parameter::getE() const
{
    return E;
}

long Parameter::getStartTime() const
{
    return START_TIME;
}

long Parameter::getEndTime() const
{
    return END_TIME;
}

int Parameter::getDeltaE() const
{
    return Δe;
}

int Parameter::getDeltaS() const
{
    return Δs;
}

ChameleonHash *Parameter::getChameHash() const
{
    return chame_hash;
}

EVP_MD_CTX *Parameter::getDigest() const
{
    return digest;
}

std::string Parameter::getG() const
{
    return G;
}

EVP_CIPHER_CTX *Parameter::getAesCipher() const
{
    return AesCipher;
}

unsigned char *Parameter::getNonce() const
{
    return nonce;
}

const std::vector<int> &Parameter::getChHash() const
{
    return CH_hash;
}

const std::vector<std::string> &Parameter::getMemberCipher() const
{
    return Member_cipher;
}

const std::vector<EC_POINT *> &Parameter::getChKey() const
{
    return CH_key;
}

const std::vector<std::string> &Parameter::getMerkleProof() const
{
    return merkle_proof;
}

int Parameter::getProofLen() const
{
    return proof_len;
}

std::string Parameter::getGpk() const
{
    return gpk;
}
