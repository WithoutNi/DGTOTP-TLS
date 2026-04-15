#ifndef UTIL_H
#define UTIL_H

#include <cstring>
#include <string>
#include <vector>

#define ID_LENGTH 16
#define SG_LENGTH 1

/// Generate commitment from password and finished message
/// @param[in] password    Password vector
/// @param[in] fin_msg     Finished message
/// @param[in] fin_msg_len Finished message length
/// @return Commitment hash as hexadecimal string
std::string ComGen(const std::vector<std::string> &password, unsigned char *fin_msg, size_t fin_msg_len);

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

/// Return a shared protocol start time for local demos.
/// Both server and client should call the same helper instead of generating
/// independent timestamps inside Parameter::init().
long getSharedProtocolStartTimeMillis();

#endif
