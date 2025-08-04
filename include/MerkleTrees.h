#ifndef MERKLE_TREES_H
#define MERKLE_TREES_H

#include <string>
#include <vector>
#include <openssl/evp.h>

/**
 * MerkleTrees类 - 对应Java中的MerkleTrees类
 * 实现Merkle树功能
 */
class MerkleTrees {
public:
    // 交易列表
    std::vector<std::string> txList;
    
    // Merkle根
    std::string root;
    
    // SHA256上下文
    static EVP_MD_CTX* digest;

    /**
     * 构造函数
     * @param txList 交易列表
     */
    MerkleTrees(const std::vector<std::string>& txList);
    
    /**
     * 析构函数
     */
    ~MerkleTrees();

    /**
     * 生成Merkle树
     */
    void merkle_tree();

    /**
     * 获取新的交易列表
     * @param tempTxList 临时交易列表
     * @return 新的交易列表
     */
    static std::vector<std::string> getNewTxList(const std::vector<std::string>& tempTxList);

    /**
     * Merkle验证
     * @param proof 证明
     * @param verify_point 验证点
     * @param root 根
     * @param index 索引
     * @return 验证结果 (1成功，0失败)
     */
    static int Verify(const std::vector<std::string>& proof, const std::string& verify_point, 
                      const std::string& root, int index);

    /**
     * 获取节点树
     * @param vp_set 验证点集合
     * @return 节点树
     */
    static std::vector<std::vector<std::string>> get_tree(const std::vector<std::string>& vp_set);

    /**
     * 获取证明
     * @param tree 树
     * @param node 节点
     * @param index 索引
     * @return 证明
     */
    static std::vector<std::string> Get_Proof(const std::vector<std::vector<std::string>>& tree, 
                                             const std::string& node, int index);

    /**
     * 获取树根
     * @return 树根
     */
    std::string getRoot();
};

#endif // MERKLE_TREES_H