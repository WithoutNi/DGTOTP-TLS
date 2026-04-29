#define _POSIX_C_SOURCE 199309L

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <ctime>
#include <vector>

#include <openssl/rand.h>
#include <openssl/sha.h>

#include "AS.h"
#include "DGTOTP.h"
#include "DGTOTP_PRF.h"
#include "cycles.h"
#include "util.h"

#define NTESTS 100

static long getCurrentTimeMillis()
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return static_cast<long>(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

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

int main()
{
    setbuf(stdout, NULL);
    init_cpucycles();

    const long sharedStartTime = getSharedProtocolStartTimeMillis();
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
    printf("Parameters: k = %ld, m = %ld, U = %d, T_s = %ld,  T_e = %ld, Δe = %d, Δs = %d\n",
           SECURITY_PARAMETER_BITS, SG_NUM, groupMemberCount,
           sharedStartTime, endTime, verificationPeriod, passwordGenerationPeriod);
    fprintf(fp, "k = %ld, m = %ld, U = %d, T_s = %ld,  T_e = %ld, Δe = %d, Δs = %d\n",
            SECURITY_PARAMETER_BITS, SG_NUM, groupMemberCount,
            sharedStartTime, endTime, verificationPeriod, passwordGenerationPeriod);

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

    std::vector<int> pwVerifyResults(NTESTS, 0);

    MEASURE("PwVerify..", 1, {
        pwVerifyResults[i] = dgtotpVec[memberSGIds[i]].Verify(passwords[i], protocolTime);
    });
    save_result(fp, "PwVerify", t, NTESTS);

    std::vector<std::string> openedIds(NTESTS);

    MEASURE("Open..", 1, {
        openedIds[i] = dgtotpVec[memberSGIds[i]].Open(passwords[i], protocolTime);
    });
    save_result(fp, "Open", t, NTESTS);

    std::vector<int> revokeResults(NTESTS, 0);

    MEASURE("Revoke..", 1, {
        revokeResults[i] = dgtotpVec[memberSGIds[i]].Revoke(memberIds[i]);
    });
    save_result(fp, "Revoke", t, NTESTS);

    printf("TagCheck results:");
    fprintf(fp, "TagCheckResults");
    for (size_t j = 0; j < NTESTS; ++j)
    {
        printf(" %d", tagCheckResults[j]);
        fprintf(fp, " %d", tagCheckResults[j]);
    }
    printf("\n");
    fprintf(fp, "\n");

    printf("CMVerify results:");
    fprintf(fp, "ComVerifyResults");
    for (size_t j = 0; j < NTESTS; ++j)
    {
        printf(" %d", cmVerifyResults[j]);
        fprintf(fp, " %d", cmVerifyResults[j]);
    }
    printf("\n");
    fprintf(fp, "\n");

    printf("PwVerify results:");
    fprintf(fp, "PwVerifyResults");
    for (size_t j = 0; j < NTESTS; ++j)
    {
        printf(" %d", pwVerifyResults[j]);
        fprintf(fp, " %d", pwVerifyResults[j]);
    }
    printf("\n");
    fprintf(fp, "\n");

    printf("Raw cycle samples saved to benchmark_dgtotp.txt\n");

    for (size_t j = 0; j < setupSkSke.size(); ++j)
    {
        free(setupSkSke[j]);
    }
    fclose(fp);
    return 0;
}
