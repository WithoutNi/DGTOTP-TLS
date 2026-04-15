#include "util.h"

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ec.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>

std::string ComGen(const std::vector<std::string> &pw,
                   unsigned char *finmsg,
                   size_t finmsg_len)
{
    // Validate password format
    if (pw.size() < 3)
    {
        throw std::runtime_error("Invalid password format");
    }

    // Buffers to store hash values
    unsigned char UCM[SHA256_DIGEST_LENGTH];
    unsigned char SCM[SHA256_DIGEST_LENGTH];

    // Calculate UCM = SHA256(pw, "used")
    // 1. Initialize context
    SHA256_CTX sha256_ucm;
    SHA256_Init(&sha256_ucm);

    // 2. Add all password components
    for (const auto &part : pw)
    {
        SHA256_Update(&sha256_ucm, part.c_str(), part.length());
    }

    // 3. Add "used" string
    const std::string used_str = "used";
    SHA256_Update(&sha256_ucm, used_str.c_str(), used_str.length());

    // 4. Compute final hash
    SHA256_Final(UCM, &sha256_ucm);

    // Calculate SCM = SHA256(pw, finmsg)
    // 1. Initialize context
    SHA256_CTX sha256_scm;
    SHA256_Init(&sha256_scm);

    // 2. Add all password components
    for (const auto &part : pw)
    {
        SHA256_Update(&sha256_scm, part.c_str(), part.length());
    }

    // 3. Add Finished message
    SHA256_Update(&sha256_scm, finmsg, finmsg_len);

    // 4. Compute final hash
    SHA256_Final(SCM, &sha256_scm);

    // Convert both hashes to hexadecimal strings
    std::string ucm_hex = bytesToHex(UCM, SHA256_DIGEST_LENGTH, true);
    std::string scm_hex = bytesToHex(SCM, SHA256_DIGEST_LENGTH, true);

    // Return concatenated result with separator
    return ucm_hex + scm_hex; // Format: "UCM:SCM"
}

void prf1(unsigned char *out, size_t outlen, unsigned char *ki, size_t key_len, const unsigned char *msg, size_t msg_len)
{
    // Compute HMAC-SHA256
    unsigned char hmac_result[SHA256_DIGEST_LENGTH];
    unsigned int hmac_len;

    HMAC(EVP_sha256(),
         ki, key_len,
         msg, msg_len,
         hmac_result, &hmac_len);

    memcpy(out, hmac_result, outlen);
}

void prf(unsigned char *out, size_t outlen, unsigned char *ki, size_t key_len, int index)
{
    // Prepare HMAC input data (convert integer j to byte sequence)
    unsigned char input_data[sizeof(int)];
    memcpy(input_data, &index, sizeof(int));

    // Compute HMAC-SHA256
    unsigned char hmac_result[SHA256_DIGEST_LENGTH];
    unsigned int hmac_len;

    HMAC(EVP_sha256(),
         ki, key_len,
         input_data, sizeof(int),
         hmac_result, &hmac_len);

    memcpy(out, hmac_result, outlen);
}

std::string bytesToString(const char *data, size_t length)
{
    if (data == nullptr || length == 0)
    {
        return "";
    }
    return std::string(reinterpret_cast<const char *>(data), length);
}

std::string bytesToHex(const unsigned char *data, size_t length, bool uppercase)
{
    std::string hex_string;
    hex_string.reserve(length * 2);

    static const char hex_digits_lower[] = "0123456789abcdef";
    static const char hex_digits_upper[] = "0123456789ABCDEF";

    const char *hex_digits = uppercase ? hex_digits_upper : hex_digits_lower;

    for (size_t i = 0; i < length; i++)
    {
        hex_string.push_back(hex_digits[data[i] >> 4]);
        hex_string.push_back(hex_digits[data[i] & 0x0F]);
    }

    return hex_string;
}

std::vector<unsigned char> HexToBytes(const unsigned char *hex_data, size_t length)
{
    if (length % 2 != 0)
    {
        throw std::invalid_argument("Hex data length must be even");
    }

    std::vector<unsigned char> result;
    result.reserve(length / 2);

    for (size_t i = 0; i < length; i += 2)
    {
        // Convert two hex characters to one byte
        unsigned char high_char = hex_data[i];
        unsigned char low_char = hex_data[i + 1];

        // Convert hex character to numeric value
        auto hexCharToValue = [](unsigned char c) -> unsigned char
        {
            if (c >= '0' && c <= '9')
                return c - '0';
            if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;
            if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;
            throw std::invalid_argument("Invalid hex character");
        };

        unsigned char byte_value = (hexCharToValue(high_char) << 4) | hexCharToValue(low_char);
        result.push_back(byte_value);
    }

    return result;
}

void printBytes(const unsigned char *data, size_t len)
{
    if (!data)
    {
        std::cout << "nullptr";
        return;
    }
    for (size_t i = 0; i < len; ++i)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(data[i]) << "";
    }
}

std::string string_to_hex(const std::string &input)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');

    for (char c : input)
    {
        ss << std::setw(2) << static_cast<unsigned int>(static_cast<unsigned char>(c));
    }

    return ss.str();
}

size_t bytesToInt(const unsigned char *bytes)
{
    if (bytes == nullptr)
    {
        throw std::invalid_argument("Null pointer passed to bytesToInt");
    }

    int value = 0;
    value |= (bytes[0] & 0xFF);
    value |= (bytes[1] & 0xFF) << 8;
    value |= (bytes[2] & 0xFF) << 16;
    value |= (bytes[3] & 0xFF) << 24;

    return (size_t)value;
}

long getSharedProtocolStartTimeMillis()
{
    using namespace std::chrono;

    const long sync_window_ms = 10 * 60 * 1000;
    const long now_ms = duration_cast<milliseconds>(
                            system_clock::now().time_since_epoch())
                            .count();

    return (now_ms / sync_window_ms) * sync_window_ms;
}
