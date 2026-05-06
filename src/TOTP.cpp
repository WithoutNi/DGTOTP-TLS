#include "TOTP.h"
#include "Parameter.h"
#include "util.h"
#include <cstring>
#include <sstream>
#include <iomanip>

// ===================== Constructor/Destructor =====================

TOTP::TOTP()
{
}

TOTP::~TOTP()
{
    freeCacheByte();
    if (digest != nullptr)
    {
        EVP_MD_CTX_free(digest);
        digest = nullptr;
    }
}

// ===================== Modify Methods =====================

void TOTP::Setup(Parameter &params)
{
    // Initialize member variables using parameter instance
    k = params.getK();
    N = params.getN();
    VERIFY_POINT = "";
    SK_SEED = "";
    digest = nullptr;
    memset(sha256, 0, sizeof(sha256));
    cache_byte = nullptr;
    N = (int)((params.getEndTime() - params.getStartTime()) / params.getDeltaS());
}

std::string TOTP::PInit(const std::string &SK_SEED)
{
    freeCacheByte();
    cache_byte = toBytes(SK_SEED);
    for (int i = 1; i <= N; i++)
    {
        unsigned char *temp = Hash_Sha256(cache_byte, 32);
        memcpy(cache_byte, temp, 32);
        free(temp);
    }
    VERIFY_POINT = std::string(reinterpret_cast<char *>(cache_byte), 32);
    return VERIFY_POINT;
}

std::string TOTP::PGen(const std::string &SK_SEED, long pw_sequence)
{
    freeCacheByte();
    unsigned char *temp_bytes = toBytes(SK_SEED);
    cache_byte = (unsigned char *)malloc(32);
    memcpy(cache_byte, temp_bytes, 32);
    free(temp_bytes);
    for (int i = 0; i < N - pw_sequence - 1; i++)
    {
        unsigned char *temp = Hash_Sha256(cache_byte, 32);
        memcpy(cache_byte, temp, 32);
        free(temp);
    }
    std::string result(reinterpret_cast<char *>(cache_byte), 32);
    return result;
}

int TOTP::Verify(const std::string &VERIFY_POINT, const std::string &password, long pw_sequence)
{
    int check_out = 0;
    if (VERIFY_POINT.length() != 32 || password.length() != 32)
    {
        return check_out;
    }

    freeCacheByte();
    cache_byte = (unsigned char *)malloc(32);
    memcpy(cache_byte, password.data(), 32);

    for (int i = 0; i < pw_sequence + 1; i++)
    {
        unsigned char *temp = Hash_Sha256(cache_byte, 32);
        memcpy(cache_byte, temp, 32);
        free(temp);
    }

    if (std::string(reinterpret_cast<char *>(cache_byte), 32) == VERIFY_POINT)
    {
        check_out = 1;
    }

    return check_out;
}

// ===================== Access Methods =====================

int TOTP::getK() const
{
    return k;
}

int TOTP::getN() const
{
    return N;
}

std::string TOTP::getVerifyPoint() const
{
    return VERIFY_POINT;
}

std::string TOTP::getSkSeed() const
{
    return SK_SEED;
}

EVP_MD_CTX *TOTP::getDigest() const
{
    return digest;
}

const unsigned char *TOTP::getSha256() const
{
    return sha256;
}

unsigned char *TOTP::getCacheByte() const
{
    return cache_byte;
}

// ===================== Static Methods =====================

std::string TOTP::byte2hex(const unsigned char *b, size_t len)
{
    std::stringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0');

    for (size_t i = 0; i < len; i++)
    {
        ss << std::setw(2) << static_cast<int>(b[i]);
    }

    return ss.str();
}

unsigned char *TOTP::toBytes(const std::string &str)
{
    if (str.empty())
    {
        return (unsigned char *)malloc(0);
    }

    size_t len = str.length() / 2;
    unsigned char *bytes = (unsigned char *)malloc(len);

    for (size_t i = 0; i < len; i++)
    {
        std::string byteString = str.substr(i * 2, 2);
        bytes[i] = (unsigned char)strtol(byteString.c_str(), nullptr, 16);
    }

    return bytes;
}

unsigned char *TOTP::Hash_Sha256(const unsigned char *tem, size_t len)
{
    unsigned char *result = (unsigned char *)malloc(32);
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

    EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(mdctx, tem, len);
    EVP_DigestFinal_ex(mdctx, result, nullptr);

    EVP_MD_CTX_free(mdctx);
    return result;
}

unsigned char *TOTP::Hash_Sha256(const std::string &message)
{
    return Hash_Sha256((const unsigned char *)message.c_str(), message.length());
}

void TOTP::freeCacheByte()
{
    if (cache_byte != nullptr)
    {
        free(cache_byte);
        cache_byte = nullptr;
    }
}
