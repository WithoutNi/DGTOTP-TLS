#include "MerkleTrees.h"
#include "Parameter.h"
#include "Member.h"
#ifndef UTIL_H
#include "util.h"
#endif
#include <cmath>
#include <algorithm>

MerkleTrees::MerkleTrees(const std::vector<std::string> &txList)
{
    this->txList = txList;
    this->root = "";
}

MerkleTrees::~MerkleTrees()
{
}

void MerkleTrees::merkle_tree()
{
    std::vector<std::string> tempTxList = txList;
    std::vector<std::string> newTxList = this->getNewTxList(tempTxList);

    while (newTxList.size() != 1)
    {
        newTxList = this->getNewTxList(newTxList);
    }

    root = newTxList[0];
}

std::vector<std::string> MerkleTrees::getNewTxList(const std::vector<std::string> &tempTxList)
{
    std::vector<std::string> newTxList;
    int index = 0;

    while (index < tempTxList.size())
    {
        // Left child
        std::string left = tempTxList[index];
        index++;

        // Right child
        std::string right = "";
        if (index != tempTxList.size())
        {
            right = tempTxList[index];
        }

        // SHA256 hash
        unsigned char *hash = Parameter::Sha256(left + right);
        std::string sha2HexValue = Member::byte2hex(hash, 32);
        free(hash);

        newTxList.push_back(sha2HexValue);
        index++;
    }

    return newTxList;
}

int MerkleTrees::Verify(const std::vector<std::string> &proof, const std::string &root_verify_point,
                        const std::string &root, int index)
{
    std::vector<std::string> proof_tem;
    int vp_index = -1;

    for (size_t i = 0; i < proof.size(); i++)
    {
        if (proof[i] == "")
        {
            proof_tem.push_back(root_verify_point);
            vp_index = static_cast<int>(proof_tem.size()) - 1;
        }
        else
        {
            proof_tem.push_back(proof[i]);
        }
    }

    if (vp_index == -1)
    {
        return 0;
    }

    std::string current = root_verify_point;

    while (proof_tem.size() > 1)
    {
        std::string combined;

        if (index % 2 == 0)
        {
            if (vp_index + 1 >= static_cast<int>(proof_tem.size()))
            {
                combined = proof_tem[vp_index];
            }
            else
            {
                combined = proof_tem[vp_index] + proof_tem[vp_index + 1];
            }

            unsigned char *hash = Parameter::Sha256(combined);
            current = Member::byte2hex(hash, 32);
            free(hash);

            proof_tem[vp_index] = current;
            if (vp_index + 1 < static_cast<int>(proof_tem.size()))
            {
                proof_tem.erase(proof_tem.begin() + vp_index + 1);
            }
        }
        else
        {
            if (vp_index == 0)
            {
                return 0;
            }

            combined = proof_tem[vp_index - 1] + proof_tem[vp_index];

            unsigned char *hash = Parameter::Sha256(combined);
            current = Member::byte2hex(hash, 32);
            free(hash);

            proof_tem[vp_index] = current;
            proof_tem.erase(proof_tem.begin() + vp_index - 1);
            vp_index = vp_index - 1;
        }

        index = index / 2;
    }

    return current == root ? 1 : 0;
}

std::vector<std::vector<std::string>> MerkleTrees::get_tree(const std::vector<std::string> &vp_set)
{
    int height = (int)ceil(log2(vp_set.size()));
    std::vector<std::vector<std::string>> tree(height, std::vector<std::string>(vp_set.size()));

    int length = vp_set.size();
    tree[0] = vp_set;

    std::vector<std::string> hash_tem;
    std::vector<std::string> level_node = vp_set;

    int level = 1;

    while (true)
    {
        if (length == 2)
            break;

        for (int i = 0; i < length; i += 2)
        {
            if (i + 1 != length)
            {
                unsigned char *hash = Parameter::Sha256(level_node[i] + level_node[i + 1]);
                hash_tem.push_back(Member::byte2hex(hash, 32));
                free(hash);
            }
            else
            {
                unsigned char *hash = Parameter::Sha256(level_node[i]);
                hash_tem.push_back(Member::byte2hex(hash, 32));
                free(hash);
            }
        }

        level_node.clear();
        for (size_t j = 0; j < hash_tem.size(); j++)
        {
            level_node.push_back(hash_tem[j]);
            tree[level][j] = hash_tem[j];
        }

        hash_tem.clear();
        length = level_node.size();
        level++;

        if (length == 2)
            break;
    }

    return tree;
}

std::vector<std::string> MerkleTrees::Get_Proof(const std::vector<std::vector<std::string>> &tree,
                                                const std::string &node, int index)
{
    std::vector<std::string> proof_list;
    proof_list.push_back("");

    for (size_t i = 0; i < tree.size(); i++)
    {
        if (index % 2 == 0)
        {
            if (index + 1 < static_cast<int>(tree[i].size()) && !tree[i][index + 1].empty())
            {
                proof_list.push_back(tree[i][index + 1]);
            }
            index = index / 2;
        }
        else
        {
            proof_list.insert(proof_list.begin(), tree[i][index - 1]);
            index = index / 2;
        }
    }

    return proof_list;
}

std::string MerkleTrees::getRoot() const
{
    return this->root;
}
