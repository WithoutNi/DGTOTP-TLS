#include "Verifier.h"
#include "Parameter.h"
#include "ChameleonHash.h"
#include "MerkleTrees.h"
#include "TOTP.h"
#include "Member.h"
#include "util.h"
#include <cstring>
#include <ctime>
#include <cmath>

int Verifier::Verify(const std::vector<std::string> &password, long time, Parameter &params)
{
    // Get current verification epoch
    current_verify_epoch = (int)((time - params.getStartTime()) / params.getDeltaE());

    // Calculate password sequence number
    int pw_sequence = (time - current_verify_epoch * params.getDeltaE() - params.getStartTime()) / params.getDeltaS();

    // Get TOTP verification point (byte array)
    unsigned char *cache_tem = TOTP::toBytes(password[0]);

    // Calculate verification point
    for (int i = 0; i < pw_sequence + 1; i++)
    {
        unsigned char *temp = Parameter::Sha256(cache_tem, 32);
        memcpy(cache_tem, temp, 32);
        free(temp);
    }

    // TOTP verification point (string)
    std::string vp = Member::byte2hex(cache_tem, 32);

    // Get permuted MPI Id index
    int per_id_index = 0;
    for (int j = 0; j < params.getU(); j++)
    {
        if (params.getMemberCipher()[j] == password[2])
        {
            per_id_index = j;
        }
    }

    // Calculate chameleon hash value
    unsigned char *vp_bytes = Parameter::Sha256(vp + password[2] + std::to_string(current_verify_epoch));
    int vp_point = params.getChameHash()->eval(vp_bytes, 32, params.getChKey()[per_id_index],
                                               (unsigned char *)password[1].c_str(), password[1].length());

    // Verify chameleon hash value
    if (vp_point != params.getChHash()[per_id_index])
    {
        std::cout << "ChameleonHash eval Error!" << std::endl;
        std::cout << "In verify, CH_hash[" << per_id_index << "]= " << params.getChHash()[per_id_index] << std::endl;
        free(cache_tem);
        free(vp_bytes);
        return 0;
    }

    std::vector<std::string> ch_hash(params.getU());
    for (int i = 0; i < params.getU(); i++)
    {
        ch_hash[i] = std::to_string(params.getChHash()[i]);
    }
    // sub_tree.resize((int)ceil(log2(params.getU())), std::vector<std::string>(params.getU()));
    MerkleTrees merkle_tree(ch_hash);
    // sub_tree = merkle_tree.get_tree(ch_hash);
    merkle_tree.merkle_tree();
    verifier_root = merkle_tree.getRoot();

    // TOTP Verify
    TOTP totp;
    totp.Setup(params);
    int res1 = totp.Verify(vp, password[0], pw_sequence);
    if (res1 != 1)
    {
        std::cout << "TOTP verify Error!" << std::endl;
        std::cout << "TOTP verify result: " << res1 << std::endl;
        free(cache_tem);
        free(vp_bytes);
        return 0;
    }
    // Merkle tree Verify
    int res2 = merkle_tree.Verify(params.getMerkleProof(), verifier_root, params.getGpk(), current_verify_epoch);
    if (res2 != 1)
    {
        std::cout << "merkle trees verify Error!" << std::endl;
        std::cout << "merkle trees verify result: " << res2 << std::endl;
        free(cache_tem);
        free(vp_bytes);
        return 0;
    }

    free(cache_tem);
    free(vp_bytes);
    return 1;
}
