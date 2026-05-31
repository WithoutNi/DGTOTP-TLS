#include <iostream>
#include <cstring>
#include <string>
#include <vector>
#include <ctime>
#include <chrono>
#include <stdexcept>
#include <unistd.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "DGTOTP.h"
#include "DGTOTP_PRF.h"
#include "AS.h"
#include "RA.h"
#include "util.h"

#define VERIFIER_PORT 4433
#define CLIENT_PORT 4435
#define BUFFER_SIZE 1024

static unsigned char received_msg[BUFFER_SIZE];
static size_t received_msg_len = 0;

SSL_CTX *create_context()
{
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        perror("SSL_CTX_new failed");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_context(SSL_CTX *ctx)
{
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_num_tickets(ctx, 0);
    if (!SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256"))
    {
        fprintf(stderr, "Failed to set ciphersuites\n");
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

// Function implementation
std::vector<std::vector<unsigned char>> TagGen(
    const Parameter &params,
    AS &as,
    const unsigned char *received_msg,
    size_t received_msg_len)
{
    const size_t commitment_len = 2 * SHA256_DIGEST_LENGTH;
    const size_t single_commitment_len = SHA256_DIGEST_LENGTH;

    // Add boundary check
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
        std::cout << "Received commitment was already in AS, abort!" << std::endl;
        return {};
    }

    Skeys shared_keys = as.QuerySkeysBySGId(com.SGId);
    if (shared_keys.empty())
    {
        throw std::runtime_error("Shared key collection is empty");
    }

    std::vector<std::vector<unsigned char>> tag_collection;
    long time1 = getCurrentTimeMillis();
    int current_epoch_j = (int)((time1 - params.getStartTime()) / params.getDeltaE());
    std::cout << "In Server, current_epoch_j=" << std::dec << current_epoch_j << std::endl;
    std::string kg_input = std::string("KG") + std::to_string(current_epoch_j);
    std::string kt_input = std::string("KT") + SG;
    std::string tag_input = std::string("Tag") +
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

        // kij=F1(ki,"KG"||j)
        prf1(kij, KEY_LENGTH_BYTES, const_cast<unsigned char *>(shared_key.key.data()), shared_key.key.size(),
             reinterpret_cast<const unsigned char *>(kg_input.data()), kg_input.size());
        // k_tag=F1(kij,"KT"||SG)
        prf1(k_tag, KEY_LENGTH_BYTES, kij, KEY_LENGTH_BYTES,
             reinterpret_cast<const unsigned char *>(kt_input.data()), kt_input.size());
        // tag=F1(k_tag,"Tag"||CM)
        prf1(tag, KEY_LENGTH_BYTES, k_tag, KEY_LENGTH_BYTES,
             reinterpret_cast<const unsigned char *>(tag_input.data()), tag_input.size());

        std::cout << "tag: ";
        printBytes(tag, KEY_LENGTH_BYTES);
        std::cout << std::endl;

        tag_collection.emplace_back(tag, tag + KEY_LENGTH_BYTES);
    }

    if (tag_collection.empty())
    {
        throw std::runtime_error("No valid shared keys found for tag generation");
    }

    printf("match tag number: %ld\n", tag_collection.size());
    return tag_collection;
}

// Setup initializes all subgroup RA instances and AS-side
// secret-key seeds used to derive subgroup shared keys.
void Setup(int securityParameter,
           int subgroupCount,
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

int main()
{
    SSL_CTX *ctx, *ctx1;
    int client_sockfd, verifier_sockfd, client_fd, client_fd1;
    struct sockaddr_in server_addr, client_addr, server_addr1;
    socklen_t client_len = sizeof(client_addr);

    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    const long sharedStartTime = getCurrentTimeMillis();
    writeProtocolStartTimeMillis(sharedStartTime);
    std::cout << "Protocol start time written to "
              << getProtocolStartTimeFilePath() << ": "
              << sharedStartTime << std::endl;
    const int groupMemberCount = 10;
    const int verificationPeriod = 300000;
    const int passwordGenerationPeriod = 5000;
    const long endTime = sharedStartTime + EPOCH_COUNT * verificationPeriod;

    // Pre-initialize all subgroup-specific DGTOTP instances.
    std::vector<DGTOTP> dgtotpVec(SG_NUM);
    std::vector<unsigned char *> sk_ske(SG_NUM);
    AS as;

    Setup(SECURITY_PARAMETER_BITS, SG_NUM, groupMemberCount, sharedStartTime, endTime,
          verificationPeriod, passwordGenerationPeriod, dgtotpVec, sk_ske);

    long currentTime = getCurrentTimeMillis();
    std::cout << "current time: " << currentTime << std::endl;

    // Create SSL context
    ctx = create_context();
    configure_context(ctx);

    // client-server TLS connection
    // Create TCP socket
    client_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(CLIENT_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    bind(client_sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    listen(client_sockfd, 5);
    std::string memberId;
    int selectedSGId = -1;

    printf("TLS 1.3 Server listening on port %d\n", CLIENT_PORT);

    // Accept client connection
    client_fd = accept(client_sockfd, (struct sockaddr *)&client_addr, &client_len);
    SSL *client_ssl = SSL_new(ctx);
    SSL_set_fd(client_ssl, client_fd);

    if (SSL_accept(client_ssl))
    {
        printf("TLS 1.3 handshake successful\n");
        // Receive data
        char buf[BUFFER_SIZE];
        int bytes = SSL_read(client_ssl, buf, sizeof(buf) - 1);
        if (bytes > 0)
        {
            buf[bytes] = '\0';
            // Check if it's username content
            if (strstr(buf, "memberId:"))
            {
                printf("Received memberId of join member\n");
                // extract username
                unsigned char *content = (unsigned char *)(buf + strlen("memberId:"));
                size_t content_len = bytes - strlen("memberId:");
                memberId = bytesToString((const char *)content, content_len);
                std::cout << "memberId_string: " << memberId << std::endl;

                selectedSGId = SGMap(k_sg, sizeof(k_sg), memberId);
                if (selectedSGId < 0 || static_cast<size_t>(selectedSGId) >= SG_NUM)
                {
                    throw std::runtime_error("Computed SGId out of range");
                }

                std::cout << "Selected SGId: " << selectedSGId << std::endl;
                std::cout << "Selected group name: " << dgtotpVec[selectedSGId].getParameter().getG() << std::endl;

                const long joinTime = getCurrentTimeMillis();
                dgtotpVec[selectedSGId].PInit(memberId);
                DGTOTP::JoinReceipt joinReceipt = dgtotpVec[selectedSGId].JoinAndExportReceipt(memberId, joinTime);
                Skey SkeyID;
                SkeyID.SGId = selectedSGId;
                SkeyID.key.resize(KEY_LENGTH_BYTES);
                unsigned char rv[KEY_LENGTH_BYTES];
                RAND_bytes(rv, KEY_LENGTH_BYTES);
                std::string msg = "SK" + bytesToHex(rv, KEY_LENGTH_BYTES);
                // SkeyID.key = F1(sk_ske, "SK"||rv);
                prf1(SkeyID.key.data(), SkeyID.key.size(),
                     sk_ske[selectedSGId], KEY_LENGTH_BYTES,
                     reinterpret_cast<const unsigned char *>(msg.c_str()), msg.length());
                as.AddSkey(SkeyID);

                std::cout << "RA shared key of the join member: ";
                printBytes(joinReceipt.shared_key.data(), joinReceipt.shared_key.size());
                std::cout << std::endl;
                std::cout << "Alpha ID of the join member: ";
                printBytes(joinReceipt.alpha_bytes.data(), joinReceipt.alpha_bytes.size());
                std::cout << std::endl;
                std::cout << "AS shared key of the join member: ";
                printBytes(SkeyID.key.data(), SkeyID.key.size());
                std::cout << std::endl;

                size_t total_length = KEY_LENGTH_BYTES + 4 + KEY_LENGTH_BYTES;

                // Create buffer and copy data
                std::vector<unsigned char> buffer;
                buffer.reserve(total_length);

                // Copy first pointer data (KEY_LENGTH_BYTES bytes)
                buffer.insert(buffer.end(), joinReceipt.shared_key.begin(), joinReceipt.shared_key.end());

                // Copy second pointer data (4 bytes)
                buffer.insert(buffer.end(), joinReceipt.alpha_bytes.begin(), joinReceipt.alpha_bytes.end());

                // Copy AS shared key (KEY_LENGTH_BYTES bytes)
                buffer.insert(buffer.end(), SkeyID.key.begin(), SkeyID.key.end());

                // Send actual data
                SSL_write(client_ssl, buffer.data(), buffer.size());
                printf("Sent RA key, alpha, and AS key to member\n");
            }
        }
    }
    SSL_shutdown(client_ssl);
    SSL_free(client_ssl);
    close(client_fd);
    SSL_CTX_free(ctx);
    close(client_sockfd);

    std::cout << std::endl;
    std::cout << "********************************" << std::endl;
    std::cout << std::endl;

    // Create SSL context
    ctx1 = create_context();
    configure_context(ctx1);

    // Create TCP socket
    verifier_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&server_addr1, 0, sizeof(server_addr1));
    server_addr1.sin_family = AF_INET;
    server_addr1.sin_port = htons(VERIFIER_PORT);
    server_addr1.sin_addr.s_addr = INADDR_ANY;

    bind(verifier_sockfd, (struct sockaddr *)&server_addr1, sizeof(server_addr1));
    listen(verifier_sockfd, 5);

    printf("TLS 1.3 Server listening on port %d\n", VERIFIER_PORT);

    client_fd1 = accept(verifier_sockfd, (struct sockaddr *)&client_addr, &client_len);
    SSL *verifier_ssl = SSL_new(ctx1);
    SSL_set_fd(verifier_ssl, client_fd1);

    // Simulate group member joining
    for (int i = 0; i < TOTAL_MEMBER_NUMBER; i++)
    {
        unsigned char new_ID[ID_LENGTH_BYTES];
        RAND_bytes(new_ID, ID_LENGTH_BYTES);
        std::string new_memberId = bytesToHex(new_ID, ID_LENGTH_BYTES);
        int new_SGId = SGMap(k_sg, sizeof(k_sg), new_memberId);
        if (!(dgtotpVec[new_SGId].getRA().IsJoinedMember(new_memberId)))
        {
            if (dgtotpVec[new_SGId].getRA().getJoinedMemberCount() >=
                dgtotpVec[new_SGId].getRA().getU())
            {
                continue;
            }
            const long T = getCurrentTimeMillis();
            dgtotpVec[new_SGId].PInit(new_memberId);
            dgtotpVec[new_SGId].Join(new_memberId, T);
            Skey new_SkeyID;
            new_SkeyID.SGId = new_SGId;
            new_SkeyID.key.resize(KEY_LENGTH_BYTES);
            unsigned char new_rv[KEY_LENGTH_BYTES];
            RAND_bytes(new_rv, KEY_LENGTH_BYTES);
            std::string new_msg = "SK" + bytesToHex(new_rv, KEY_LENGTH_BYTES);
            // new_SkeyID.key = F1(sk_ske, "SK"||rv);
            prf1(new_SkeyID.key.data(), new_SkeyID.key.size(),
                 sk_ske[new_SGId], KEY_LENGTH_BYTES,
                 reinterpret_cast<const unsigned char *>(new_msg.c_str()), new_msg.length());
            as.AddSkey(new_SkeyID);
        }
    }

    // Perform TLS handshake
    if (SSL_accept(verifier_ssl))
    {
        printf("TLS 1.3 handshake successful\n");
        bool keep_connection = true;
        while (keep_connection)
        {
            // Receive data
            char buf[BUFFER_SIZE];
            int bytes = SSL_read(verifier_ssl, buf, sizeof(buf) - 1);
            if (bytes > 0)
            {
                buf[bytes] = '\0';

                const size_t msg_prefix_len = strlen("MSG:");
                const size_t pw_prefix_len = strlen("PW:");

                // Check if it's MSG content
                if (bytes >= static_cast<int>(msg_prefix_len) &&
                    memcmp(buf, "MSG:", msg_prefix_len) == 0)
                {
                    printf("Received MSG content from verifier\n");

                    const unsigned char *content = (const unsigned char *)(buf + msg_prefix_len);

                    // extract commitment+SG from received message (MSG:commitment+SG)
                    size_t content_len = bytes - msg_prefix_len;

                    // Save commitment+SG
                    memcpy(received_msg, content, content_len);
                    received_msg_len = content_len;

                    // Print original message
                    printf("Original Received message (%zu bytes):\n", received_msg_len);
                    for (size_t i = 0; i < received_msg_len; i++)
                    {
                        printf("%02X", received_msg[i]);
                    }
                    printf("\n");

                    const Parameter &params = dgtotpVec[selectedSGId].getParameter();
                    std::vector<std::vector<unsigned char>> tags = TagGen(params, as, received_msg, received_msg_len);
                    // Calculate total bytes
                    size_t total_size = 0;
                    for (const auto &tag : tags)
                    {
                        total_size += tag.size();
                    }

                    if (tags.empty())
                    {
                        std::cout << "No tags generated for the received commitment" << std::endl;
                        continue;
                    }

                    // Create continuous buffer
                    std::vector<unsigned char> buffer;
                    buffer.reserve(total_size);

                    // Concatenate all tags
                    for (const auto &tag : tags)
                    {
                        buffer.insert(buffer.end(), tag.begin(), tag.end());
                    }

                    // Send tags
                    SSL_write(verifier_ssl, buffer.data(), buffer.size());
                    printf("Sent compute tags to verifier\n");
                    printf("\n");
                }
                else if (bytes >= static_cast<int>(pw_prefix_len) &&
                         memcmp(buf, "PW:", pw_prefix_len) == 0)
                {
                    printf("Received password pw from verifier\n");
                    std::string received_data(buf, bytes);
                    // remove PW:
                    std::string pw_data = received_data.substr(3);

                    // Extract using known lengths (ensure correct length)
                    DGTOTP::Password password;
                    if (pw_data.length() >= 32 + 32 + 20)
                    {
                        password.totp_password = pw_data.substr(0, 32);
                        password.collision_randomness = pw_data.substr(32, 32);
                        password.identity_ciphertext = pw_data.substr(32 + 32, 20);
                    }
                    else
                    {
                        throw std::runtime_error("Received password data too short");
                    }

                    std::cout << "TOTP Password: " << string_to_hex(password.totp_password) << std::endl;
                    std::cout << "Chameleon Hash: " << string_to_hex(password.collision_randomness) << std::endl;
                    std::cout << "Identity Ciphertext: " << string_to_hex(password.identity_ciphertext) << std::endl;

                    // Verify DGTOTP password using a fresh timestamp and current epoch metadata.
                    const long verifyTime = getCurrentTimeMillis();
                    dgtotpVec[selectedSGId].refreshPublishedState(verifyTime);
                    int verifyResult = dgtotpVec[selectedSGId].Verify(password, verifyTime);
                    std::cout << "Verify result for the correct password and verify epoch: " << (verifyResult == 1 ? "success" : "failure") << std::endl;
                    std::cout << std::endl;

                    std::string openResult = dgtotpVec[selectedSGId].Open(password, verifyTime);
                    std::cout << "Open ID for the correct password and verify epoch: " << openResult << std::endl;
                    std::cout << std::endl;

                    std::string response = "Verify result:";
                    if (verifyResult == 1)
                        response += "success";
                    else
                        response += "failure";
                    SSL_write(verifier_ssl, response.c_str(), response.length());
                }
            }
            else
            {
                // Close connection
                printf("closed the connection\n");
                keep_connection = false;
            }
        }
    }
    else
    {
        ERR_print_errors_fp(stderr);
    }

    SSL_shutdown(verifier_ssl);
    SSL_free(verifier_ssl);
    close(client_fd1);
    SSL_CTX_free(ctx1);
    close(verifier_sockfd);
    for (size_t i = 0; i < sk_ske.size(); ++i)
    {
        free(sk_ske[i]);
    }

    return 0;
}
