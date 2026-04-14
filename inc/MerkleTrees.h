#ifndef MERKLE_TREES_H
#define MERKLE_TREES_H

#include <string>
#include <vector>
#include <openssl/evp.h>

/**
 * MerkleTrees class - Implements Merkle tree functionality
 */
class MerkleTrees
{
public:
    // ===================== Constructor/Destructor =====================

    /// Constructor
    /// @param[in] txList Transaction list
    MerkleTrees(const std::vector<std::string> &txList);

    /// Destructor
    ~MerkleTrees();

    // ===================== Modify Methods =====================

    /// Build Merkle tree
    void merkle_tree();

    /// Create new transaction list for tree level
    /// @param[in] tempTxList Temporary transaction list
    /// @return New transaction list for next level
    std::vector<std::string> getNewTxList(const std::vector<std::string> &tempTxList);

    /// Verify Merkle proof
    /// @param[in] proof Proof list
    /// @param[in] verify_point Verification point
    /// @param[in] root Root hash
    /// @param[in] index Node index
    /// @return Verification result (1 success, 0 failure)
    int Verify(std::vector<std::string> &proof, const std::string &verify_point,
               const std::string &root, int index);

    /// Build Merkle tree structure
    /// @param[in] vp_set Set of verification points
    /// @return Tree structure as vector of levels
    std::vector<std::vector<std::string>> get_tree(const std::vector<std::string> &vp_set);

    /// Generate Merkle proof for node
    /// @param[in] tree Tree structure
    /// @param[in] node Target node
    /// @param[in] index Node index
    /// @return Proof list for verification
    std::vector<std::string> Get_Proof(const std::vector<std::vector<std::string>> &tree,
                                       const std::string &node, int index);

    // ===================== Access Methods =====================

    /// Get Merkle root
    /// @return Root hash
    std::string getRoot() const;

private:
    // ===================== Member Variables =====================

    // Transaction list
    std::vector<std::string> txList;

    // Merkle root
    std::string root;
};

#endif // MERKLE_TREES_H
