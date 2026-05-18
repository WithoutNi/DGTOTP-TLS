#define _POSIX_C_SOURCE 199309L

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <stdexcept>
#include <string>
#include <ctime>
#include <vector>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "AS.h"
#include "ChameleonHash.h"
#include "DGTOTP.h"
#include "DGTOTP_PRF.h"
#include "Member.h"
#include "MerkleTrees.h"
#include "TOTP.h"
#include "cycles.h"
#include "util.h"

#define NTESTS 1000

static int cmp_llu(const void *a, const void *b)
{
    const unsigned long long lhs = *static_cast<const unsigned long long *>(a);
    const unsigned long long rhs = *static_cast<const unsigned long long *>(b);
    if (lhs < rhs)
        return -1;
    if (lhs > rhs)
        return 1;
    return 0;
}

static unsigned long long median(unsigned long long *l, size_t llen)
{
    qsort(l, llen, sizeof(unsigned long long), cmp_llu);
    if (llen % 2)
        return l[llen / 2];
    return (l[llen / 2 - 1] + l[llen / 2]) / 2;
}

static void delta(unsigned long long *l, size_t llen)
{
    for (size_t i = 0; i < llen - 1; i++)
    {
        l[i] = l[i + 1] - l[i];
    }
}

static std::string commaString(unsigned long long n)
{
    std::string text = std::to_string(n);
    for (int i = static_cast<int>(text.length()) - 3; i > 0; i -= 3)
    {
        text.insert(static_cast<size_t>(i), ",");
    }
    return text;
}

static void display_result(double result, unsigned long long *l, size_t llen, unsigned long long mul)
{
    unsigned long long med;

    result /= NTESTS;
    delta(l, NTESTS + 1);
    med = median(l, llen);

    const std::string medText = commaString(med);
    const std::string scaledText = commaString(mul * med);
    printf("avg. %12.2lf us (%8.2lf ms); median %16s cycles, %5llux: %16s cycles\n",
           result, result / 1e3, medText.c_str(), mul, scaledText.c_str());
}

static void save_result(FILE *fp, const char *preamble, unsigned long long *l, size_t llen)
{
    fprintf(fp, "%s", preamble);
    for (size_t i = 0; i < llen; i++)
    {
        fprintf(fp, " %llu ", l[i]);
    }
    fprintf(fp, "\n");
}

#define MEASURE_GENERIC(TEXT, MUL, FNCALL, CORR)                                                                         \
    printf("%-12s", TEXT);                                                                                               \
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);                                                                     \
    for (i = 0; i < NTESTS; i++)                                                                                         \
    {                                                                                                                    \
        t[i] = cpucycles() / CORR;                                                                                       \
        FNCALL;                                                                                                          \
    }                                                                                                                    \
    t[NTESTS] = cpucycles();                                                                                             \
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stop);                                                                      \
    result = ((double)(stop.tv_sec - start.tv_sec) * 1e6 + (double)(stop.tv_nsec - start.tv_nsec) / 1e3) / (double)CORR; \
    display_result(result, t, NTESTS, MUL);
#define MEASURT(TEXT, MUL, FNCALL)         \
    MEASURE_GENERIC(                       \
        TEXT, MUL,                         \
        do {                               \
            for (int j = 0; j < 1000; j++) \
            {                              \
                FNCALL;                    \
            }                              \
        } while (0);                       \
        ,                                  \
        1000);
#define MEASURE(TEXT, MUL, FNCALL) MEASURE_GENERIC(TEXT, MUL, FNCALL, 1)

static std::string makeMemberId(size_t index)
{
    unsigned char id[ID_LENGTH_BYTES] = {0};
    for (size_t i = 0; i < ID_LENGTH_BYTES; ++i)
    {
        id[i] = static_cast<unsigned char>((index * 131 + i * 17) & 0xFF);
    }
    return bytesToHex(id, ID_LENGTH_BYTES);
}

static void Setup(int securityParameter,
                  size_t subgroupCount,
                  int groupMemberCount,
                  long sharedStartTime,
                  long endTime,
                  int verificationPeriod,
                  int passwordGenerationPeriod,
                  std::vector<DGTOTP> &dgtotpVec,
                  std::vector<unsigned char *> &sk_ske)
{
    if (dgtotpVec.size() != subgroupCount || sk_ske.size() != subgroupCount)
    {
        throw std::invalid_argument("Setup containers must match subgroup count");
    }

    for (size_t i = 0; i < subgroupCount; ++i)
    {
        const std::string groupName = "DGTOTP" + std::to_string(i);
        dgtotpVec[i].RASetup(securityParameter, groupName, groupMemberCount, sharedStartTime,
                             endTime, verificationPeriod, passwordGenerationPeriod);
        sk_ske[i] = DGTOTP_PRF::createKey();
    }
}

static std::vector<std::vector<unsigned char>> TagGen(
    const Parameter &params,
    AS &as,
    const unsigned char *received_msg,
    size_t received_msg_len)
{
    const size_t commitment_len = 2 * SHA256_DIGEST_LENGTH;
    const size_t single_commitment_len = SHA256_DIGEST_LENGTH;

    if (received_msg_len < commitment_len + SG_LENGTH_BYTES)
    {
        throw std::runtime_error("Received message too short");
    }

    std::string cm(reinterpret_cast<const char *>(received_msg), commitment_len);
    std::string ucm = cm.substr(0, single_commitment_len);
    std::string scm = cm.substr(single_commitment_len, single_commitment_len);

    std::string SG(reinterpret_cast<const char *>(received_msg + commitment_len), SG_LENGTH_BYTES);

    Com com;
    com.SGId = static_cast<unsigned char>(SG[0]);
    com.CM.UCM = ucm;
    com.CM.SCM = scm;

    if (!as.CheckAndAddCM(com))
    {
        return {};
    }

    Skeys shared_keys = as.QuerySkeysBySGId(com.SGId);
    if (shared_keys.empty())
    {
        throw std::runtime_error("Shared key collection is empty");
    }

    std::vector<std::vector<unsigned char>> tag_collection;
    const long time = getCurrentTimeMillis();
    const int current_epoch_j = static_cast<int>((time - params.getStartTime()) / params.getDeltaE());
    const std::string kg_input = std::string("KG") + std::to_string(current_epoch_j);
    const std::string kt_input = std::string("KT") + SG;
    const std::string tag_input = std::string("Tag") +
                                  std::string(reinterpret_cast<const char *>(received_msg), commitment_len);

    for (const auto &shared_key : shared_keys)
    {
        if (shared_key.key.empty())
        {
            continue;
        }

        unsigned char kij[KEY_LENGTH_BYTES];
        unsigned char k_tag[KEY_LENGTH_BYTES];
        unsigned char tag[KEY_LENGTH_BYTES];

        prf1(kij, KEY_LENGTH_BYTES, const_cast<unsigned char *>(shared_key.key.data()), shared_key.key.size(),
             reinterpret_cast<const unsigned char *>(kg_input.data()), kg_input.size());
        prf1(k_tag, KEY_LENGTH_BYTES, kij, KEY_LENGTH_BYTES,
             reinterpret_cast<const unsigned char *>(kt_input.data()), kt_input.size());
        prf1(tag, KEY_LENGTH_BYTES, k_tag, KEY_LENGTH_BYTES,
             reinterpret_cast<const unsigned char *>(tag_input.data()), tag_input.size());

        tag_collection.emplace_back(tag, tag + KEY_LENGTH_BYTES);
    }

    return tag_collection;
}

static int TagCheck(unsigned char ki[],
                    int current_epoch_j,
                    const std::string &SG,
                    const pw_CM &commitment,
                    const unsigned char *tags,
                    size_t tag_len)
{
    unsigned char kij[KEY_LENGTH_BYTES];
    const std::string kg_input = std::string("KG") + std::to_string(current_epoch_j);
    prf1(kij, KEY_LENGTH_BYTES, ki, KEY_LENGTH_BYTES,
         reinterpret_cast<const unsigned char *>(kg_input.data()), kg_input.size());

    unsigned char tag_key[KEY_LENGTH_BYTES];
    const std::string kt_input = std::string("KT") + SG;
    prf1(tag_key, KEY_LENGTH_BYTES, kij, KEY_LENGTH_BYTES,
         reinterpret_cast<const unsigned char *>(kt_input.data()), kt_input.size());

    unsigned char tag[KEY_LENGTH_BYTES];
    const std::string tag_input = std::string("Tag") + commitment.UCM + commitment.SCM;
    prf1(tag, KEY_LENGTH_BYTES, tag_key, KEY_LENGTH_BYTES,
         reinterpret_cast<const unsigned char *>(tag_input.data()), tag_input.size());

    for (size_t i = 0; i + KEY_LENGTH_BYTES <= tag_len; i += KEY_LENGTH_BYTES)
    {
        if (memcmp(tags + i, tag, KEY_LENGTH_BYTES) == 0)
        {
            return 1;
        }
    }
    return 0;
}

static std::vector<unsigned char> flattenTagCollection(const std::vector<std::vector<unsigned char>> &tag_collection)
{
    size_t total_size = 0;
    for (const auto &tag : tag_collection)
    {
        total_size += tag.size();
    }

    std::vector<unsigned char> buffer;
    buffer.reserve(total_size);
    for (const auto &tag : tag_collection)
    {
        buffer.insert(buffer.end(), tag.begin(), tag.end());
    }

    return buffer;
}

static std::vector<unsigned char> buildReceivedMessage(const pw_CM &commitment, int sgId)
{
    const std::string SG = std::string(1, static_cast<char>(sgId));
    const std::string payload = commitment.UCM + commitment.SCM + SG;
    return std::vector<unsigned char>(payload.begin(), payload.end());
}

static std::vector<unsigned char> buildPasswordMessage(const DGTOTP::Password &password)
{
    const std::string payload = "PW:" + password.totp_password +
                                password.collision_randomness +
                                password.identity_ciphertext;
    return std::vector<unsigned char>(payload.begin(), payload.end());
}

static int CMVerify(const unsigned char *msg,
                    size_t msg_len,
                    unsigned char *fin_msg,
                    size_t fin_msg_len,
                    const unsigned char *com,
                    size_t com_len)
{
    const size_t prefix_len = 3;
    const size_t totp_len = 32;
    const size_t randomness_len = 32;
    const size_t identity_len = 20;
    const size_t password_len = totp_len + randomness_len + identity_len;

    if (msg_len < prefix_len + password_len || memcmp(msg, "PW:", prefix_len) != 0)
    {
        return 0;
    }

    const char *pw_data = reinterpret_cast<const char *>(msg + prefix_len);
    std::vector<std::string> password;
    password.push_back(std::string(pw_data, totp_len));
    password.push_back(std::string(pw_data + totp_len, randomness_len));
    password.push_back(std::string(pw_data + totp_len + randomness_len, identity_len));

    const pw_CM commitment = CMGen(password, fin_msg, fin_msg_len);
    const std::string serializedCommitment = commitment.UCM + commitment.SCM;
    if (serializedCommitment.size() != com_len)
    {
        return 0;
    }

    return memcmp(com, serializedCommitment.data(), com_len) == 0 ? 1 : 0;
}

static std::string BenchmarkOpenFirstEpoch(const DGTOTP &dgtotp,
                                           const DGTOTP::Password &structuredPassword,
                                           long time)
{
    const int fixed_epoch = 0;
    const std::vector<std::string> password = structuredPassword.toVector();
    const Parameter &params = dgtotp.getParameter();
    const RA &ra = dgtotp.getRA();

    int per_id_index = -1;
    for (int j = 0; j < params.getU(); j++)
    {
        if (params.getMemberCipher()[j] == password[2])
        {
            per_id_index = j;
            break;
        }
    }

    if (per_id_index < 0)
    {
        return "";
    }

    const long pw_sequence = (time - params.getStartTime()) / params.getDeltaS();
    if (pw_sequence < 0)
    {
        return "";
    }

    unsigned char *cache_tem = static_cast<unsigned char *>(malloc(32));
    memcpy(cache_tem, password[0].data(), 32);

    for (int i = 0; i < pw_sequence + 1; i++)
    {
        unsigned char *temp = Parameter::Sha256(cache_tem, 32);
        memcpy(cache_tem, temp, 32);
        free(temp);
    }

    std::string vp(reinterpret_cast<char *>(cache_tem), 32);
    std::string vp_hex = Member::byte2hex(cache_tem, 32);
    free(cache_tem);

    unsigned char *vp_bytes = Parameter::Sha256(vp_hex + password[2] + std::to_string(fixed_epoch));
    int vp_point = params.getChameHash()->eval(vp_bytes, 32,
                                               params.getChKey()[per_id_index],
                                               reinterpret_cast<unsigned char *>(const_cast<char *>(password[1].c_str())),
                                               password[1].length());

    cache_tem = DGTOTP_PRF::ksAES(params.getG() + "PM" + std::to_string(fixed_epoch), ra.getKsCipher());
    unsigned int seed = 0;
    memcpy(&seed, cache_tem, sizeof(unsigned int));
    std::vector<int> regen_per_table = const_cast<RA &>(ra).Permutation(seed);
    free(cache_tem);

    int original_member_index = -1;
    for (int i = 0; i < params.getU(); i++)
    {
        if (regen_per_table[i] == per_id_index)
        {
            original_member_index = i;
            break;
        }
    }

    if (original_member_index == -1 || vp_point != params.getChHash()[per_id_index])
    {
        free(vp_bytes);
        return "";
    }

    const std::vector<std::string> &smt = ra.getSMT();
    if (smt.empty())
    {
        free(vp_bytes);
        return "";
    }

    TOTP totp;
    totp.Setup(const_cast<Parameter &>(params));
    MerkleTrees verifier_tree(smt);
    if (verifier_tree.Verify(params.getMerkleProof(), smt[fixed_epoch], params.getGpk(), fixed_epoch) == 1 &&
        totp.Verify(vp, password[0], pw_sequence) == 1)
    {
        cache_tem = DGTOTP_PRF::ksAES(params.getG() + "KS" + std::to_string(original_member_index), ra.getKsCipher());

        unsigned char *ke = DGTOTP_PRF::jdkAES("KeyGen" + std::to_string(fixed_epoch), cache_tem);
        unsigned char *re = DGTOTP_PRF::jdkAES("Rand" + std::to_string(fixed_epoch), cache_tem);
        unsigned char *id_bytes = RA::ASE_dec(ke,
                                              reinterpret_cast<unsigned char *>(const_cast<char *>(params.getMemberCipher()[per_id_index].c_str())),
                                              params.getMemberCipher()[per_id_index].length(),
                                              re, params.getNonce());

        int ID_plain = Parameter::bytesToInt(id_bytes);
        const std::vector<std::string> &idlg = ra.getIDLG();
        std::string opened_id;
        if (ID_plain >= 0 && static_cast<size_t>(ID_plain) < idlg.size())
        {
            opened_id = idlg[ID_plain];
        }

        free(cache_tem);
        free(ke);
        free(re);
        free(id_bytes);
        free(vp_bytes);

        return opened_id;
    }

    free(vp_bytes);
    return "";
}

struct TLS13AeadCiphertext
{
    std::vector<unsigned char> tls_header; // 5 bytes, used as AAD
    std::vector<unsigned char> ciphertext; // encrypted(payload || content_type)
    std::vector<unsigned char> tag;        // 16 bytes
};

/**
 * TLS 1.3-like AES-128-GCM encryption.
 *
 * payload:      application plaintext, e.g., Com = 69 bytes
 * content_type: TLSInnerPlaintext content type, usually 0x17 for application_data
 * tls_header:   5-byte TLS record header, used as AAD
 * key:          16-byte AES-128 key
 * iv:           12-byte GCM nonce / TLS per-record nonce
 */
TLS13AeadCiphertext TLS13_AES128_GCM_Enc(
    const unsigned char *payload,
    size_t payload_len,
    unsigned char content_type,
    const unsigned char tls_header[5],
    const unsigned char key[16],
    const unsigned char iv[12])
{
    TLS13AeadCiphertext out;
    out.tls_header.assign(tls_header, tls_header + 5);
    out.ciphertext.resize(payload_len + 1);
    out.tag.resize(16);

    std::vector<unsigned char> in(payload_len + 1);
    if (payload_len > 0)
    {
        std::memcpy(in.data(), payload, payload_len);
    }
    in[payload_len] = content_type;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr)
    {
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }

    int len = 0;
    int n = 0;
    bool ok =
        EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1 &&
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv) == 1 &&
        EVP_EncryptUpdate(ctx, nullptr, &len, tls_header, 5) == 1 &&
        EVP_EncryptUpdate(ctx, out.ciphertext.data(), &len, in.data(), static_cast<int>(in.size())) == 1;

    n = len;
    ok = ok &&
         EVP_EncryptFinal_ex(ctx, out.ciphertext.data() + n, &len) == 1 &&
         EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out.tag.data()) == 1;
    n += len;

    EVP_CIPHER_CTX_free(ctx);
    if (!ok)
    {
        throw std::runtime_error("AES-128-GCM encryption failed");
    }

    out.ciphertext.resize(n);
    return out;
}

/**
 * TLS 1.3 AES-128-GCM decryption.
 *
 * Returns the original payload, excluding the final TLS content_type byte.
 */
std::vector<unsigned char> TLS13_AES128_GCM_Dec(
    const unsigned char *ciphertext,
    size_t ciphertext_len,
    const unsigned char tag[16],
    const unsigned char tls_header[5],
    const unsigned char key[16],
    const unsigned char iv[12],
    unsigned char expected_content_type = 0x17)
{
    std::vector<unsigned char> out(ciphertext_len);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr)
    {
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }

    int len = 0;
    int n = 0;
    bool ok =
        EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1 &&
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv) == 1 &&
        EVP_DecryptUpdate(ctx, nullptr, &len, tls_header, 5) == 1 &&
        EVP_DecryptUpdate(ctx, out.data(), &len, ciphertext, static_cast<int>(ciphertext_len)) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<unsigned char *>(tag)) == 1;

    n = len;
    ok = ok && EVP_DecryptFinal_ex(ctx, out.data() + n, &len) == 1;
    n += len;

    EVP_CIPHER_CTX_free(ctx);
    if (!ok || n < 1)
    {
        throw std::runtime_error("AES-128-GCM decryption or tag verification failed");
    }

    out.resize(n);
    if (out.back() != expected_content_type)
    {
        throw std::runtime_error("Unexpected TLS content type");
    }

    out.pop_back();
    return out;
}

int main()
{
    setbuf(stdout, NULL);
    init_cpucycles();

    const long sharedStartTime = getCurrentTimeMillis();
    const int securityParameter = SECURITY_PARAMETER_BITS;
    const int subgroupCount = SG_NUM;
    const int groupMemberCount = 64;
    const int verificationPeriod = 300000;
    const int passwordGenerationPeriod = 5000;
    const long endTime = sharedStartTime + EPOCH_COUNT * verificationPeriod;
    const long protocolTime = getCurrentTimeMillis();
    unsigned char fin_msg[32] = {0};
    RAND_bytes(fin_msg, sizeof(fin_msg));

    unsigned char prf_key[KEY_LENGTH_BYTES] = {0};
    unsigned char prf_out[KEY_LENGTH_BYTES] = {0};
    RAND_bytes(prf_key, KEY_LENGTH_BYTES);
    const std::string prf_message = "benchmark message";

    const size_t tls13_payload_len = 69;
    const unsigned char tls13_content_type = 0x17;
    const unsigned char tls13_header[5] = {
        0x17, 0x03, 0x03, 0x00,
        static_cast<unsigned char>(tls13_payload_len + 1 + 16)};
    unsigned char tls13_key[16] = {0};
    unsigned char tls13_iv[12] = {0};
    std::vector<unsigned char> tls13_payload(tls13_payload_len);
    RAND_bytes(tls13_key, sizeof(tls13_key));
    RAND_bytes(tls13_iv, sizeof(tls13_iv));
    RAND_bytes(tls13_payload.data(), static_cast<int>(tls13_payload.size()));

    unsigned long long t[NTESTS + 1];
    struct timespec start, stop;
    double result;
    unsigned int i;

    FILE *fp = fopen("benchmark_dgtotp.txt", "w+");
    if (fp == nullptr)
    {
        perror("benchmark_dgtotp.txt");
        return 1;
    }

    printf("DGTOTP-TLS benchmark\n");
    printf("Running %d iterations.\n", NTESTS);
    fprintf(fp, "DGTOTP benchmark\n");
    fprintf(fp, "iterations=%d\n", NTESTS);
    printf("Parameters: k = %ld, m = %ld, U = %d, T_s = %ld,  T_e = %ld, delta_e = %d, delta_s = %d\n",
           SECURITY_PARAMETER_BITS, SG_NUM, groupMemberCount,
           sharedStartTime, endTime, verificationPeriod, passwordGenerationPeriod);
    fprintf(fp, "k = %ld, m = %ld, U = %d, T_s = %ld,  T_e = %ld, delta_e = %d, delta_s = %d\n",
            SECURITY_PARAMETER_BITS, SG_NUM, groupMemberCount,
            sharedStartTime, endTime, verificationPeriod, passwordGenerationPeriod);

    TLS13AeadCiphertext tls13_ciphertext;
    std::vector<unsigned char> tls13_plaintext;

    printf("TLS_AES_128_GCM_SHA256 AEAD params: TLS header = 5 bytes, content type = 1 byte, GCM tag = 16 bytes, overhead = 22 bytes, payload = %zu bytes\n",
           tls13_payload_len);
    fprintf(fp, "TLS_AES_128_GCM_SHA256 AEAD params: TLS header = 5 bytes, content type = 1 byte, GCM tag = 16 bytes, overhead = 22 bytes, payload = %zu bytes\n",
            tls13_payload_len);

    MEASURE("AEADEnc..", 1, {
        tls13_ciphertext = TLS13_AES128_GCM_Enc(
            tls13_payload.data(), tls13_payload.size(), tls13_content_type,
            tls13_header, tls13_key, tls13_iv);
    });
    save_result(fp, "AEADEnc", t, NTESTS);

    MEASURE("AEADDec..", 1, {
        tls13_plaintext = TLS13_AES128_GCM_Dec(
            tls13_ciphertext.ciphertext.data(), tls13_ciphertext.ciphertext.size(),
            tls13_ciphertext.tag.data(), tls13_header, tls13_key, tls13_iv,
            tls13_content_type);
    });
    save_result(fp, "AEADDec", t, NTESTS);

    std::vector<DGTOTP> dgtotpVec(SG_NUM);
    std::vector<unsigned char *> setupSkSke(SG_NUM, nullptr);

    MEASURE("Setup..", 1, {
        for (size_t j = 0; j < setupSkSke.size(); ++j)
        {
            free(setupSkSke[j]);
            setupSkSke[j] = nullptr;
        }
        Setup(securityParameter, SG_NUM, groupMemberCount, sharedStartTime, endTime,
              verificationPeriod, passwordGenerationPeriod, dgtotpVec, setupSkSke);
    });
    save_result(fp, "Setup", t, NTESTS);

    MEASURE("prf1..", 1, prf1(prf_out, KEY_LENGTH_BYTES, prf_key, KEY_LENGTH_BYTES, reinterpret_cast<const unsigned char *>(prf_message.data()), prf_message.size()));
    save_result(fp, "prf1", t, NTESTS);

    std::vector<std::string> memberIds(NTESTS);
    std::vector<int> memberSGIds(NTESTS);
    for (size_t j = 0; j < memberIds.size(); ++j)
    {
        memberIds[j] = makeMemberId(j);
    }

    MEASURE("SGIdGen..", 1, {
        memberSGIds[i] = SGIdGen(k_sg, sizeof(k_sg), memberIds[i]);
    });
    save_result(fp, "SGIdGen", t, NTESTS);

    MEASURE("PInit..", 1, dgtotpVec[memberSGIds[i]].PInit(memberIds[i]));
    save_result(fp, "PInit", t, NTESTS);

    MEASURE("Join..", 1, dgtotpVec[memberSGIds[i]].Join(memberIds[i], protocolTime));
    save_result(fp, "Join", t, NTESTS);

    std::vector<std::vector<unsigned char>> kiVec(NTESTS);
    AS as;
    for (size_t j = 0; j < memberIds.size(); ++j)
    {
        Skey skey;
        skey.SGId = memberSGIds[j];
        skey.key.resize(KEY_LENGTH_BYTES);
        unsigned char rv[KEY_LENGTH_BYTES];
        RAND_bytes(rv, KEY_LENGTH_BYTES);
        std::string msg = "SK" + bytesToHex(rv, KEY_LENGTH_BYTES);
        prf1(skey.key.data(), skey.key.size(),
             setupSkSke[memberSGIds[j]], KEY_LENGTH_BYTES,
             reinterpret_cast<const unsigned char *>(msg.c_str()), msg.length());
        kiVec[j] = skey.key;
        as.AddSkey(skey);
    }

    std::vector<DGTOTP::Password> passwords(NTESTS);

    MEASURE("PwGen..", 1, {
        passwords[i] = dgtotpVec[memberSGIds[i]].PwGen(memberIds[i], protocolTime);
    });
    save_result(fp, "PwGen", t, NTESTS);

    std::vector<pw_CM> commitments(NTESTS);

    MEASURE("CMGen..", 1, {
        commitments[i] = CMGen(passwords[i].toVector(), fin_msg, sizeof(fin_msg));
    });
    save_result(fp, "CMGen", t, NTESTS);

    std::vector<std::vector<unsigned char>> messages(NTESTS);
    for (size_t j = 0; j < messages.size(); ++j)
    {
        messages[j] = buildReceivedMessage(commitments[j], memberSGIds[j]);
    }

    std::vector<std::vector<unsigned char>> passwordMessages(NTESTS);
    std::vector<std::vector<unsigned char>> commitmentBuffers(NTESTS);
    for (size_t j = 0; j < passwordMessages.size(); ++j)
    {
        passwordMessages[j] = buildPasswordMessage(passwords[j]);
        const std::string serializedCommitment = commitments[j].UCM + commitments[j].SCM;
        commitmentBuffers[j] = std::vector<unsigned char>(serializedCommitment.begin(), serializedCommitment.end());
    }

    std::vector<std::vector<std::vector<unsigned char>>> tagCollections(NTESTS);

    MEASURE("TagGen..", 1, {
        tagCollections[i] =
            TagGen(dgtotpVec[memberSGIds[i]].getParameter(), as, messages[i].data(), messages[i].size());
    });
    save_result(fp, "TagGen", t, NTESTS);

    const int current_epoch_j =
        static_cast<int>((getCurrentTimeMillis() - sharedStartTime) / verificationPeriod);

    std::vector<std::vector<unsigned char>> tagBuffers(NTESTS);
    for (size_t j = 0; j < tagBuffers.size(); ++j)
    {
        tagBuffers[j] = flattenTagCollection(tagCollections[j]);
    }

    std::vector<int> tagCheckResults(NTESTS, 0);

    MEASURE("TagCheck..", 1, {
        tagCheckResults[i] = TagCheck(kiVec[i].data(), current_epoch_j,
                                      std::string(1, static_cast<char>(memberSGIds[i])),
                                      commitments[i], tagBuffers[i].data(), tagBuffers[i].size());
    });
    save_result(fp, "TagCheck", t, NTESTS);

    std::vector<int> cmVerifyResults(NTESTS, 0);

    MEASURE("CMVerify..", 1, {
        cmVerifyResults[i] = CMVerify(passwordMessages[i].data(), passwordMessages[i].size(),
                                      fin_msg, sizeof(fin_msg),
                                      commitmentBuffers[i].data(), commitmentBuffers[i].size());
    });
    save_result(fp, "CMVerify", t, NTESTS);

    MEASURE("GMUpdate..", 1, {
        dgtotpVec[memberSGIds[i]].refreshPublishedState(protocolTime);
    });
    save_result(fp, "GMUpdate", t, NTESTS);

    std::vector<int> pwVerifyResults(NTESTS, 0);

    MEASURE("PwVerify..", 1, {
        pwVerifyResults[i] = dgtotpVec[memberSGIds[i]].Verify(passwords[i], protocolTime);
    });
    save_result(fp, "PwVerify", t, NTESTS);

    std::vector<std::string> openedIds(NTESTS);

    MEASURE("Open..", 1, {
        openedIds[i] = BenchmarkOpenFirstEpoch(dgtotpVec[memberSGIds[i]], passwords[i], protocolTime);
    });
    save_result(fp, "Open", t, NTESTS);
    const size_t openEmptyCount = std::count(openedIds.begin(), openedIds.end(), "");

    std::vector<int> revokeResults(NTESTS, 0);

    MEASURE("Revoke..", 1, {
        revokeResults[i] = dgtotpVec[memberSGIds[i]].Revoke(memberIds[i]);
    });
    save_result(fp, "Revoke", t, NTESTS);

    size_t tagCheckSuccessCount = 0;
    for (size_t j = 0; j < NTESTS; ++j)
    {
        if (tagCheckResults[j] == 1)
        {
            tagCheckSuccessCount++;
        }
    }
    printf("TagCheck success count: %zu/%d\n", tagCheckSuccessCount, NTESTS);
    fprintf(fp, "TagCheckSuccessCount %zu/%d\n", tagCheckSuccessCount, NTESTS);

    size_t cmVerifySuccessCount = 0;
    for (size_t j = 0; j < NTESTS; ++j)
    {
        if (cmVerifyResults[j] == 1)
        {
            cmVerifySuccessCount++;
        }
    }
    printf("CMVerify success count: %zu/%d\n", cmVerifySuccessCount, NTESTS);
    fprintf(fp, "CMVerifySuccessCount %zu/%d\n", cmVerifySuccessCount, NTESTS);

    size_t pwVerifySuccessCount = 0;
    for (size_t j = 0; j < NTESTS; ++j)
    {
        if (pwVerifyResults[j] == 1)
        {
            pwVerifySuccessCount++;
        }
    }
    printf("PwVerify success count: %zu/%d\n", pwVerifySuccessCount, NTESTS);
    fprintf(fp, "PwVerifySuccessCount %zu/%d\n", pwVerifySuccessCount, NTESTS);

    printf("Open empty count: %zu\n", openEmptyCount);
    fprintf(fp, "OpenEmptyCount %zu\n", openEmptyCount);

    printf("Raw cycle samples saved to benchmark_dgtotp.txt\n");

    for (size_t j = 0; j < setupSkSke.size(); ++j)
    {
        free(setupSkSke[j]);
    }
    fclose(fp);
    return 0;
}
