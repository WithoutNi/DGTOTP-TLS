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
#ifndef UTIL_H
#include "util.h"
#endif
#include "KeyGen.h"

#define VERIFIER_CM_PORT 4433
#define RA_PORT 4437
#define BUFFER_SIZE 1024

#define CHECK_SSL_VOID(iRet, msg)                               \
    do                                                          \
    {                                                           \
        if ((iRet) <= 0)                                        \
        {                                                       \
            fprintf(stderr, "%s failed (ret=%d)\n", msg, iRet); \
            ERR_print_errors_fp(stderr);                        \
            return;                                             \
        }                                                       \
    } while (0)

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

// Configures mutual authentication (Two-Way TLS) context
void configure_mutual_auth_context(SSL_CTX *ctx)
{
    int iRet = 0;

    iRet = SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    CHECK_SSL_VOID(iRet, "SSL_CTX_set_min_proto_version");

    iRet = SSL_CTX_set_num_tickets(ctx, 0);
    CHECK_SSL_VOID(iRet, "SSL_CTX_set_num_tickets");

    iRet = SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256");
    CHECK_SSL_VOID(iRet, "SSL_CTX_set_ciphersuites");

    iRet = SSL_CTX_use_certificate_file(ctx, "AS.crt", SSL_FILETYPE_PEM);
    CHECK_SSL_VOID(iRet, "SSL_CTX_use_certificate_file");

    iRet = SSL_CTX_use_PrivateKey_file(ctx, "AS.key", SSL_FILETYPE_PEM);
    CHECK_SSL_VOID(iRet, "SSL_CTX_use_PrivateKey_file");

    iRet = SSL_CTX_check_private_key(ctx);
    CHECK_SSL_VOID(iRet, "SSL_CTX_check_private_key");

    // Enable Mutual Authentication
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    iRet = SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL);
    CHECK_SSL_VOID(iRet, "SSL_CTX_load_verify_locations");
}

// Function implementation
std::vector<std::vector<unsigned char>> TagGen(
    AS &as, int current_epoch_j, const unsigned char *received_msg,
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

    PwUsageRecord PURec;
    ;
    PURec.SGId = static_cast<unsigned char>(SG[0]);
    PURec.UCM = ucm;

    if (!as.CheckAndAddPURec(PURec))
    {
        std::cout << "Received commitment was already in AS, abort!" << std::endl;
        return {};
    }

    ConfKeyList ConfKeys = as.QueryConfKeyListBySGId(PURec.SGId);
    if (ConfKeys.empty())
    {
        throw std::runtime_error("Shared key collection is empty");
    }

    std::vector<std::vector<unsigned char>> tag_collection;
    std::cout << "In Server, current_epoch_j=" << std::dec << current_epoch_j << std::endl;
    std::string kg_input = std::string("KG") + std::to_string(current_epoch_j);
    std::string kt_input = std::string("KT") + SG;
    std::string tag_input = std::string("Tag") +
                            std::string(reinterpret_cast<const char *>(received_msg), commitment_len);

    for (const auto &confKey : ConfKeys)
    {
        if (confKey.key.empty())
        {
            continue;
        }

        unsigned char kij[KEY_LENGTH_BYTES];
        unsigned char k_tag[KEY_LENGTH_BYTES];
        unsigned char tag[KEY_LENGTH_BYTES];

        // kij=F1(ki,"KG"||j)
        prf1(kij, KEY_LENGTH_BYTES, const_cast<unsigned char *>(confKey.key.data()), confKey.key.size(),
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

/// The setup algorithm for authentication server
void ASSetup(int I, AS &as)
{
    std::string pk_AS, sk_AS;
    bool success = KeyGen(pk_AS, sk_AS);
    if (!success)
    {
        throw std::runtime_error("Failed to generate AS keys");
    }
    as.SetLocalState(pk_AS, sk_AS);
    as.InitAuthState(I);
}

int main()
{
    AS as;
    ASSetup(SG_NUM, as);
    SSL_CTX *ctx, *ctx1;
    int ra_sockfd, verifier_sockfd, ra_fd, verifier_fd;
    struct sockaddr_in server_as_addr, server_as_addr1;

    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Generate AS certificate and key if they don't exist
    std::string key_file = "AS.key";
    std::string cert_file = "AS.crt";
    if (!fileExists(key_file) || !fileExists(cert_file))
    {
        std::cout << "AS certificate or key not found, generating..." << std::endl;
        if (!GenerateKeyAndCertificate(key_file, cert_file))
        {
            std::cerr << "Failed to generate AS certificate and key" << std::endl;
            return 1;
        }
        std::cout << "AS certificate and key generated successfully" << std::endl;
    }
    else
    {
        std::cout << "AS certificate and key already exist, skipping generation" << std::endl;
    }

    // Part1：Create SSL context for RA-AS Mutual Auth TLS connection
    ctx = create_context();
    configure_mutual_auth_context(ctx);

    // Create TCP socket
    ra_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&server_as_addr, 0, sizeof(server_as_addr));
    server_as_addr.sin_family = AF_INET;
    server_as_addr.sin_port = htons(RA_PORT);
    server_as_addr.sin_addr.s_addr = INADDR_ANY;

    bind(ra_sockfd, (struct sockaddr *)&server_as_addr, sizeof(server_as_addr));
    listen(ra_sockfd, 5);

    printf("TLS 1.3 Server listening on port %d\n", RA_PORT);

    struct sockaddr_in ra_addr;
    socklen_t ra_len = sizeof(ra_addr);
    ra_fd = accept(ra_sockfd, (struct sockaddr *)&ra_addr, &ra_len);
    SSL *ra_ssl = SSL_new(ctx);
    SSL_set_fd(ra_ssl, ra_fd);

    if (SSL_accept(ra_ssl))
    {
        printf("TLS 1.3 handshake successful\n");
        bool keep_ra2as_connection = true;
        while (keep_ra2as_connection)
        {
            char buf[(KEY_LENGTH_BYTES + sizeof(int)) * TOTAL_MEMBER_NUMBER];
            int bytes = SSL_read(ra_ssl, buf, sizeof(buf) - 1);
            if (bytes > 0)
            {
                buf[bytes] = '\0';

                const size_t msg_prefix_len = strlen("ConfKeys:");
                // Check if it's ConfKeys content
                if (bytes >= static_cast<int>(msg_prefix_len) &&
                    memcmp(buf, "ConfKeys:", msg_prefix_len) == 0)
                {
                    printf("Received ConfKeys from RA\n");
                    const unsigned char *content = (const unsigned char *)(buf + msg_prefix_len);
                    size_t content_len = bytes - msg_prefix_len;

                    // Add ConfKeys
                    size_t offset = 0;
                    const size_t sgid_size = 4;
                    const size_t key_size = KEY_LENGTH_BYTES;

                    while (offset + sgid_size + key_size <= content_len)
                    {
                        uint32_t sgid_net;
                        memcpy(&sgid_net, content + offset, sgid_size);
                        uint32_t sgid = ntohl(sgid_net);
                        offset += sgid_size;

                        std::vector<unsigned char> key(content + offset, content + offset + key_size);
                        offset += key_size;

                        ConfKey confKey;
                        confKey.SGId = sgid;
                        confKey.key = key;
                        as.AddConfkey(confKey);
                    }

                    // After processing ConfKeys
                    if (offset > 0)
                    {
                        printf("Successfully parsed %zu ConfKeys from RA\n",
                               offset / (sgid_size + key_size));
                        SSL_write(ra_ssl, "OK", 2); // Send acknowledgment
                    }
                    keep_ra2as_connection = false;
                    break;
                }
            }
        }
    }
    SSL_shutdown(ra_ssl);
    SSL_free(ra_ssl);
    close(ra_fd);
    SSL_CTX_free(ctx);
    close(ra_sockfd);

    const long sharedStartTime = readProtocolStartTimeMillis();

    // Part2：Create SSL context for verifier-AS Mutual Auth TLS connection
    ctx1 = create_context();
    configure_mutual_auth_context(ctx1);

    // Create TCP socket
    verifier_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&server_as_addr1, 0, sizeof(server_as_addr1));
    server_as_addr1.sin_family = AF_INET;
    server_as_addr1.sin_port = htons(VERIFIER_CM_PORT);
    server_as_addr1.sin_addr.s_addr = INADDR_ANY;

    bind(verifier_sockfd, (struct sockaddr *)&server_as_addr1, sizeof(server_as_addr1));
    listen(verifier_sockfd, 5);

    printf("TLS 1.3 Server listening on port %d\n", VERIFIER_CM_PORT);

    struct sockaddr_in verifier_addr;
    socklen_t verifier_len = sizeof(verifier_addr);
    verifier_fd = accept(verifier_sockfd, (struct sockaddr *)&verifier_addr, &verifier_len);
    SSL *verifier_ssl = SSL_new(ctx1);
    SSL_set_fd(verifier_ssl, verifier_fd);

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

                const size_t msg_prefix_len = strlen("PURec:");
                // Check if it's PURec content
                if (bytes >= static_cast<int>(msg_prefix_len) &&
                    memcmp(buf, "PURec:", msg_prefix_len) == 0)
                {
                    printf("Received PURec content from verifier\n");

                    const unsigned char *content = (const unsigned char *)(buf + msg_prefix_len);

                    // extract commitment+SG from received message (PURec:commitment+SG)
                    size_t content_len = bytes - msg_prefix_len;

                    // Save commitment+SG
                    unsigned char received_msg[BUFFER_SIZE];
                    size_t received_msg_len = 0;
                    memcpy(received_msg, content, content_len);
                    received_msg_len = content_len;

                    // Print original message
                    printf("Original Received message (%zu bytes):\n", received_msg_len);
                    for (size_t i = 0; i < received_msg_len; i++)
                    {
                        printf("%02X", received_msg[i]);
                    }
                    printf("\n");

                    long time1 = getCurrentTimeMillis();
                    int current_epoch_j = (int)((time1 - sharedStartTime) / DELTA_E);
                    std::vector<std::vector<unsigned char>> tags = TagGen(as, current_epoch_j, received_msg, received_msg_len);
                    // Calculate total bytes
                    size_t total_size = 0;
                    for (const auto &tag : tags)
                    {
                        total_size += tag.size();
                    }

                    // Create continuous buffer
                    std::vector<unsigned char> buffer;
                    buffer.reserve(total_size);

                    // Concatenate all tags
                    for (const auto &tag : tags)
                    {
                        buffer.insert(buffer.end(), tag.begin(), tag.end());
                    }

                    // Pad to fixed length: 16 * MAX_GROUP_MEMBER
                    const size_t FIXED_LEN = 16 * MAX_GROUP_MEMBER;
                    if (buffer.size() < FIXED_LEN)
                    {
                        // Generate random padding data
                        std::vector<unsigned char> padding(FIXED_LEN - buffer.size());
                        RAND_bytes(padding.data(), padding.size());
                        buffer.insert(buffer.end(), padding.begin(), padding.end());
                    }

                    // Send tags
                    SSL_write(verifier_ssl, buffer.data(), buffer.size());
                    printf("Sent compute tags to verifier\n");
                    printf("\n");
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
    close(verifier_fd);
    SSL_CTX_free(ctx1);
    close(verifier_sockfd);

    return 0;
}