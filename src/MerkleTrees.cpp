#include "MerkleTrees.h"
#include "Parameter.h"
#include "Member.h"
#include <cmath>
#include <algorithm>

// 静态成员初始化
EVP_MD_CTX* MerkleTrees::digest = nullptr;

MerkleTrees::MerkleTrees(const std::vector<std::string>& txList) {
    this->txList = txList;
    this->root = "";
    
    if (digest == nullptr) {
        digest = EVP_MD_CTX_new();
    }
}

MerkleTrees::~MerkleTrees() {
    // 不释放digest，因为它是静态的
}

void MerkleTrees::merkle_tree() {
    std::vector<std::string> tempTxList = txList;
    std::vector<std::string> newTxList = getNewTxList(tempTxList);
    
    while (newTxList.size() != 1) {
        newTxList = getNewTxList(newTxList);
    }
    
    root = newTxList[0];
}

std::vector<std::string> MerkleTrees::getNewTxList(const std::vector<std::string>& tempTxList) {
    std::vector<std::string> newTxList;
    int index = 0;
    
    while (index < tempTxList.size()) {
        // 左子节点
        std::string left = tempTxList[index];
        index++;
        
        // 右子节点
        std::string right = "";
        if (index != tempTxList.size()) {
            right = tempTxList[index];
        }
        
        // SHA256哈希值
        unsigned char* hash = Parameter::Sha256(left + right);
        std::string sha2HexValue = Member::byte2hex(hash, 32);
        free(hash);
        
        newTxList.push_back(sha2HexValue);
        index++;
    }
    
    return newTxList;
}

int MerkleTrees::Verify(const std::vector<std::string>& proof, const std::string& verify_point, 
                        const std::string& root, int index) {
    std::string re_root;
    int result = 0;
    int vp_index = 0;
    
    std::vector<std::string> proof_tem = proof;
    
    // 查找验证点索引
    for (size_t i = 0; i < proof_tem.size(); i++) {
        if (proof_tem[i] == "") {
            proof_tem[i] = verify_point;
            vp_index = i;
            break;
        }
    }
    
    std::string str;
    while (!proof_tem.empty()) {
        if (proof_tem.size() == 1) break;
        
        if (index % 2 == 0) {
            str = proof_tem[vp_index] + proof_tem[vp_index + 1];
            unsigned char* hash = Parameter::Sha256(str);
            str = Member::byte2hex(hash, 32);
            free(hash);
            
            re_root = str;
            proof_tem[vp_index] = str;
            proof_tem.erase(proof_tem.begin() + vp_index + 1);
            
            index = index / 2;
        } else {
            str = proof_tem[vp_index - 1] + proof_tem[vp_index];
            unsigned char* hash = Parameter::Sha256(str);
            str = Member::byte2hex(hash, 32);
            free(hash);
            
            re_root = str;
            proof_tem[vp_index] = str;
            proof_tem.erase(proof_tem.begin() + vp_index - 1);
            
            vp_index = vp_index - 1;
            index = index / 2;
        }
    }
    
    if (str == root) result = 1;
    
    return result;
}

std::vector<std::vector<std::string>> MerkleTrees::get_tree(const std::vector<std::string>& vp_set) {
    int height = (int)ceil(log2(vp_set.size()));
    std::vector<std::vector<std::string>> tree(height, std::vector<std::string>(vp_set.size()));
    
    int length = vp_set.size();
    tree[0] = vp_set;
    
    std::vector<std::string> hash_tem;
    std::vector<std::string> level_node = vp_set;
    
    int level = 1;
    
    while (true) {
        if (length == 2) break;
        
        for (int i = 0; i < length; i += 2) {
            if (i + 1 != length) {
                unsigned char* hash = Parameter::Sha256(level_node[i] + level_node[i + 1]);
                hash_tem.push_back(Member::byte2hex(hash, 32));
                free(hash);
            } else {
                unsigned char* hash = Parameter::Sha256(level_node[i]);
                hash_tem.push_back(Member::byte2hex(hash, 32));
                free(hash);
            }
        }
        
        level_node.clear();
        for (size_t j = 0; j < hash_tem.size(); j++) {
            level_node.push_back(hash_tem[j]);
            tree[level][j] = hash_tem[j];
        }
        
        hash_tem.clear();
        length = level_node.size();
        level++;
        
        if (length == 2) break;
    }
    
    return tree;
}

std::vector<std::string> MerkleTrees::Get_Proof(const std::vector<std::vector<std::string>>& tree, 
                                               const std::string& node, int index) {
    std::vector<std::string> proof_list;
    proof_list.push_back("");
    
    for (size_t i = 0; i < tree.size(); i++) {
        if (index % 2 == 0) {
            proof_list.push_back(tree[i][index + 1]);
            index = index / 2;
        } else {
            proof_list.insert(proof_list.begin(), tree[i][index - 1]);
            index = index / 2;
        }
    }
    
    return proof_list;
}

std::string MerkleTrees::getRoot() {
    return this->root;
}