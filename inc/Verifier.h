#ifndef VERIFIER_H
#define VERIFIER_H

#include <string>
#include <vector>
#include <openssl/ec.h>

// Forward declaration
class Parameter;

/**
 * Verifier class - Implements verifier functionality for DGTOTP protocol
 */
class Verifier
{
public:
    /// Verify DGTOTP password
    /// @param[in] password DGTOTP password containing verification point, random number, and ciphertext
    /// @param[in] time     Current timestamp
    /// @param[in] params   Parameter instance
    /// @return Verification result (1 success, 0 failure)
    int Verify(const std::vector<std::string> &password, long time, Parameter &params);

private:
    /// Current verification epoch
    int current_verify_epoch;

    /// Sub-tree structure for verification
    std::vector<std::vector<std::string>> sub_tree;

    /// Root of sub-tree for current verification epoch
    std::string verifier_root;
};

#endif // VERIFIER_H