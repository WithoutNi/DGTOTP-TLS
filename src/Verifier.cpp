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

// Static member initialization
int Verifier::current_verify_epoch = 0;
std::string Verifier::verifier_root = "";
std::vector<std::vector<std::string>> Verifier::sub_tree;

int Verifier::Verify(const std::vector<std::string> &password, long time)
{
    // Get current verification epoch
    current_verify_epoch = (int)((time - Parameter::START_TIME) / Parameter::Δe);

    // Calculate password sequence number
    int pw_sequence = (time - current_verify_epoch * Parameter::Δe - Parameter::START_TIME) / Parameter::Δs;

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
    for (int j = 0; j < Parameter::U; j++)
    {
        if (Parameter::Member_cipher[j] == password[2])
        {
            per_id_index = j;
            // printf("per_id_index=%d\n", per_id_index);
        }
    }

    // Calculate chameleon hash value
    unsigned char *vp_bytes = Parameter::Sha256(vp + password[2] + std::to_string(current_verify_epoch));
    int vp_point = ChameleonHash::eval(vp_bytes, 32, Parameter::CH_key[per_id_index],
                                       (unsigned char *)password[1].c_str(), password[1].length());

    // Verify chameleon hash value
    if (vp_point != Parameter::CH_hash[per_id_index])
    {
        std::cout << "ChameleonHash eval Error!" << std::endl;
        std::cout << "In verify, CH_hash[" << per_id_index << "]= " << Parameter::CH_hash[per_id_index] << std::endl;
        free(cache_tem);
        free(vp_bytes);
        return 0;
    }

    std::vector<std::string> ch_hash(Parameter::U);
    for (int i = 0; i < Parameter::U; i++)
    {
        ch_hash[i] = std::to_string(Parameter::CH_hash[i]);
    }
    sub_tree.resize((int)ceil(log2(Parameter::U)), std::vector<std::string>(Parameter::U));
    sub_tree = MerkleTrees::get_tree(ch_hash);
    MerkleTrees merkle_tree(ch_hash);
    merkle_tree.merkle_tree();
    verifier_root = merkle_tree.getRoot();

    // TOTP Verify
    if (TOTP::Verify(vp, password[0], pw_sequence) != 1)
    {
        std::cout << "TOTP verify Error!" << std::endl;
        std::cout << "TOTP verify result: " << TOTP::Verify(vp, password[0], pw_sequence) << std::endl;
        free(cache_tem);
        free(vp_bytes);
        return 0;
    }
    // Merkle tree Verify
    if (MerkleTrees::Verify(Parameter::merkle_proof, verifier_root, Parameter::gpk, current_verify_epoch) != 1)
    {
        std::cout << "merkle trees verify Error!" << std::endl;
        std::cout << "merkle trees verify result: " << MerkleTrees::Verify(Parameter::merkle_proof, verifier_root, Parameter::gpk, current_verify_epoch) << std::endl;
        free(cache_tem);
        free(vp_bytes);
        return 0;
    }

    free(cache_tem);
    free(vp_bytes);
    return 1;
}