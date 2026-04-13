#ifndef VERIFIER_H
#define VERIFIER_H

#include <string>
#include <vector>
#include <openssl/ec.h>

/**
 * Verifier class - Implements verifier functionality for DGTOTP protocol
 */
class Verifier
{
public:
    /// Current verification epoch
    static int current_verify_epoch;

    /// Sub-tree structure for verification
    static std::vector<std::vector<std::string>> sub_tree;

    /// Root of sub-tree for current verification epoch
    static std::string verifier_root;

    /// Verify DGTOTP password
    /// @param[in] password DGTOTP password containing verification point, random number, and ciphertext
    /// @param[in] time     Current timestamp
    /// @return Verification result (1 success, 0 failure)
    static int Verify(const std::vector<std::string> &password, long time);
};

#endif // VERIFIER_H