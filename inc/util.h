#ifndef UTIL_H
#define UTIL_H

#include <cstring>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

#include "AS.h"

constexpr size_t SECURITY_PARAMETER_BITS = 128;
constexpr size_t KEY_LENGTH_BYTES = SECURITY_PARAMETER_BITS / 8;
constexpr size_t ID_LENGTH_BYTES = 16;
constexpr size_t SG_LENGTH_BYTES = 1;
constexpr size_t SG_NUM = 1 << (8 * SG_LENGTH_BYTES);
constexpr size_t EPOCH_COUNT = 4;
constexpr size_t TOTAL_MEMBER_NUMBER = 1178;

/// Public subgroup key shared by client/server when computing subgroup IDs.
extern const unsigned char k_sg[16];

/// Generate commitment from password and finished message
/// @param[in] password    Password vector
/// @param[in] fin_msg     Finished message
/// @param[in] fin_msg_len Finished message length
/// @return Password commitment pair containing UCM and SCM
pw_CM CMGen(const std::vector<std::string> &password, unsigned char *fin_msg, size_t fin_msg_len);

/// Pseudo-random function with message input
/// @param[out] out      Output buffer
/// @param[in]  outlen   Output buffer length
/// @param[in]  ki       Key
/// @param[in]  key_len  Key length
/// @param[in]  msg      Input message
/// @param[in]  msg_len  Message length
void prf1(unsigned char *out, size_t outlen, unsigned char *ki, size_t key_len, const unsigned char *msg, size_t msg_len);

/// Pseudo-random function with integer index
/// @param[out] out      Output buffer
/// @param[in]  outlen   Output buffer length
/// @param[in]  ki       Key
/// @param[in]  key_len  Key length
/// @param[in]  index    Integer index
void prf(unsigned char *out, size_t outlen, unsigned char *ki, size_t key_len, int index);

/// Compute subgroup identifier SGId for selecting the corresponding params/RA instance.
/// The PRF output is folded into the range [0，2^（8*SG_LENGTH_BYTES)).
/// @param[in] subgroup_key Key material used to derive the subgroup identifier
/// @param[in] key_len      Subgroup key length
/// @param[in] id           Member identity string
/// @return Integer subgroup identifier in [0, 2^(8*SG_LENGTH_BYTES))
int SGIdGen(const unsigned char *subgroup_key, size_t key_len, const std::string &id);

/// Convert byte array to string
/// @param[in] data   Byte array
/// @param[in] length Array length
/// @return String representation
std::string bytesToString(const char *data, size_t length);

/// Convert byte array to hexadecimal string
/// @param[in] data      Byte array
/// @param[in] length    Array length
/// @param[in] uppercase Use uppercase letters
/// @return Hexadecimal string
std::string bytesToHex(const unsigned char *data, size_t length, bool uppercase = true);

/// Convert hexadecimal data to byte array
/// @param[in] hex_data Hexadecimal data
/// @param[in] length   Data length
/// @return Byte array
std::vector<unsigned char> HexToBytes(const unsigned char *hex_data, size_t length);

/// Print byte array in hexadecimal format
/// @param[in] data Byte array
/// @param[in] len  Array length
void printBytes(const unsigned char *data, size_t len);

/// Convert string to hexadecimal representation
/// @param[in] input Input string
/// @return Hexadecimal string
std::string string_to_hex(const std::string &input);

/// Convert byte array to integer
/// @param[in] bytes Byte array (must be at least 4 bytes)
/// @return Integer value
size_t bytesToInt(const unsigned char *bytes);

/// Convert integer to fixed-width hexadecimal string
/// @param[in] value Integer value to be converted
/// @param[in] width Output width (in hex digits), padded with leading zeros if necessary
/// @return Hexadecimal string representation of the input value (lowercase, without "0x" prefix)
std::string intToHex(int value, int width);

/// Return the current Unix timestamp in milliseconds.
long getCurrentTimeMillis();

/// Return the start-time file path next to the running executable.
std::string getProtocolStartTimeFilePath();

/// Persist the server-generated protocol start time for local experiments.
void writeProtocolStartTimeMillis(long startTimestamp);

/// Read the server-generated protocol start time for local experiments.
long readProtocolStartTimeMillis();

#endif
