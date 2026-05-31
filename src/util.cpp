#include "util.h"
#include "Parameter.h"

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ec.h>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <fstream>
#include <stdexcept>

#include <unistd.h>

const unsigned char k_sg[16] = {
    0x44, 0x47, 0x54, 0x4F, 0x54, 0x50, 0x2D, 0x53,
    0x47, 0x2D, 0x4B, 0x45, 0x59, 0x2D, 0x30, 0x31};

pw_CM CMGen(const std::vector<std::string> &pw,
            unsigned char *finmsg,
            size_t finmsg_len)
{
    // Validate password format
    if (pw.size() < 3)
    {
        throw std::runtime_error("Invalid password format");
    }

    // Calculate UCM = SHA256(pw||"used")
    std::string ucm_input;
    for (const auto &part : pw)
    {
        ucm_input.append(part);
    }
    ucm_input.append("used");
    unsigned char *UCM = Parameter::Sha256(ucm_input);

    // Calculate SCM = SHA256(pw||finmsg||"bind")
    std::string scm_input;
    for (const auto &part : pw)
    {
        scm_input.append(part);
    }
    scm_input.append(reinterpret_cast<const char *>(finmsg), finmsg_len);
    scm_input.append("bind");
    unsigned char *SCM = Parameter::Sha256(scm_input);

    pw_CM commitment;
    commitment.UCM = std::string(reinterpret_cast<char *>(UCM), SHA256_DIGEST_LENGTH);
    commitment.SCM = std::string(reinterpret_cast<char *>(SCM), SHA256_DIGEST_LENGTH);
    free(UCM);
    free(SCM);
    return commitment;
}

void prf1(unsigned char *out, size_t outlen, unsigned char *ki, size_t key_len, const unsigned char *msg, size_t msg_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outlen1 = 0;
    int outlen2 = 0;
    std::vector<unsigned char> encrypted(msg_len + EVP_MAX_BLOCK_LENGTH);

    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, ki, nullptr);
    EVP_EncryptUpdate(ctx, encrypted.data(), &outlen1, msg, static_cast<int>(msg_len));
    EVP_EncryptFinal_ex(ctx, encrypted.data() + outlen1, &outlen2);
    EVP_CIPHER_CTX_free(ctx);

    const size_t encrypted_len = static_cast<size_t>(outlen1 + outlen2);
    if (outlen > encrypted_len)
    {
        throw std::invalid_argument("prf1 output length exceeds AES ciphertext length");
    }

    memcpy(out, encrypted.data(), outlen);
}

int SGMap(const unsigned char *subgroup_key, size_t key_len, const std::string &id)
{
    unsigned char sg_id[SG_LENGTH_BYTES];
    prf1(sg_id, SG_LENGTH_BYTES, const_cast<unsigned char *>(subgroup_key), key_len,
         reinterpret_cast<const unsigned char *>(id.data()), id.size());

    int result = 0;
    for (size_t i = 0; i < SG_LENGTH_BYTES; ++i)
    {
        result = (result << 8) | sg_id[i];
    }

    return result % static_cast<int>(SG_NUM);
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

long getCurrentTimeMillis()
{
    using namespace std::chrono;

    return duration_cast<milliseconds>(
               system_clock::now().time_since_epoch())
        .count();
}

std::string getProtocolStartTimeFilePath()
{
    char executable_path[4096];
    const ssize_t path_len = readlink("/proc/self/exe", executable_path, sizeof(executable_path) - 1);
    if (path_len > 0)
    {
        executable_path[path_len] = '\0';
        const std::string path(executable_path);
        const std::string::size_type separator = path.find_last_of('/');
        if (separator != std::string::npos)
        {
            return path.substr(0, separator + 1) + "start_time.txt";
        }
    }

    return "start_time.txt";
}

void writeProtocolStartTimeMillis(long startTimestamp)
{
    const std::string file_path = getProtocolStartTimeFilePath();
    std::ofstream out(file_path.c_str(), std::ios::out | std::ios::trunc);
    if (!out)
    {
        throw std::runtime_error("Failed to open start time file for writing: " + file_path);
    }

    out << startTimestamp << std::endl;
    if (!out)
    {
        throw std::runtime_error("Failed to write start time file: " + file_path);
    }
}

long readProtocolStartTimeMillis()
{
    const std::string file_path = getProtocolStartTimeFilePath();
    std::ifstream in(file_path.c_str());
    if (!in)
    {
        throw std::runtime_error("Failed to open start time file for reading: " + file_path);
    }

    long startTimestamp = 0;
    in >> startTimestamp;
    if (!in)
    {
        throw std::runtime_error("Invalid start time file: " + file_path);
    }

    return startTimestamp;
}
