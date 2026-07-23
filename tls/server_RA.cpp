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
#include "KeyGen.h"

#define SERVER_AS_IP "127.0.0.1"
#define CLIENT_PORT 4435
#define VERIFIER_PW_PORT 4436
#define AS_PORT 4437
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

#define CHECK_SSL_CTX(iRet, msg)                                \
    do                                                          \
    {                                                           \
        if ((iRet) <= 0)                                        \
        {                                                       \
            fprintf(stderr, "%s failed (ret=%d)\n", msg, iRet); \
            ERR_print_errors_fp(stderr);                        \
            return NULL;                                        \
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

// Create SSL context (client mode)
SSL_CTX *create_client_context()
{
    int iRet = 0;
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    iRet = (ctx != NULL) ? 1 : 0;
    CHECK_SSL_CTX(iRet, "SSL_CTX_new");

    iRet = SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    CHECK_SSL_CTX(iRet, "SSL_CTX_set_min_proto_version");

    iRet = SSL_CTX_use_certificate_file(ctx, "RA.crt", SSL_FILETYPE_PEM);
    CHECK_SSL_CTX(iRet, "SSL_CTX_use_certificate_file");

    iRet = SSL_CTX_use_PrivateKey_file(ctx, "RA.key", SSL_FILETYPE_PEM);
    CHECK_SSL_CTX(iRet, "SSL_CTX_use_PrivateKey_file");

    iRet = SSL_CTX_check_private_key(ctx);
    CHECK_SSL_CTX(iRet, "SSL_CTX_check_private_key");

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    iRet = SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL);
    CHECK_SSL_CTX(iRet, "SSL_CTX_load_verify_locations");

    return ctx;
}

// Configures standard one-way TLS context
void configure_server_auth_context(SSL_CTX *ctx)
{
    int iRet = 0;

    iRet = SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    CHECK_SSL_VOID(iRet, "SSL_CTX_set_min_proto_version");

    iRet = SSL_CTX_set_num_tickets(ctx, 0);
    CHECK_SSL_VOID(iRet, "SSL_CTX_set_num_tickets");

    iRet = SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256");
    CHECK_SSL_VOID(iRet, "SSL_CTX_set_ciphersuites");

    iRet = SSL_CTX_use_certificate_file(ctx, "RA.crt", SSL_FILETYPE_PEM);
    CHECK_SSL_VOID(iRet, "SSL_CTX_use_certificate_file");

    iRet = SSL_CTX_use_PrivateKey_file(ctx, "RA.key", SSL_FILETYPE_PEM);
    CHECK_SSL_VOID(iRet, "SSL_CTX_use_PrivateKey_file");

    iRet = SSL_CTX_check_private_key(ctx);
    CHECK_SSL_VOID(iRet, "SSL_CTX_check_private_key");
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

    iRet = SSL_CTX_use_certificate_file(ctx, "RA.crt", SSL_FILETYPE_PEM);
    CHECK_SSL_VOID(iRet, "SSL_CTX_use_certificate_file");

    iRet = SSL_CTX_use_PrivateKey_file(ctx, "RA.key", SSL_FILETYPE_PEM);
    CHECK_SSL_VOID(iRet, "SSL_CTX_use_PrivateKey_file");

    iRet = SSL_CTX_check_private_key(ctx);
    CHECK_SSL_VOID(iRet, "SSL_CTX_check_private_key");

    // Enable Mutual Authentication
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    iRet = SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL);
    CHECK_SSL_VOID(iRet, "SSL_CTX_load_verify_locations");
}

// Setup initializes all subgroup RA instances and AS-side
// secret-key seeds used to derive subgroup shared keys.
void RASetup(int k,
             struct TAUX &taux,
             size_t ℓ_ep,
             int I,
             std::vector<DGTOTP> &dgtotpVec,
             unsigned char *&sk_ske)
{
    if (dgtotpVec.size() != I)
    {
        throw std::invalid_argument("Setup containers must match subgroup count");
    }

    long T_s = taux.T_s;
    long T_e = T_s + taux.E * ℓ_ep;
    long delta_e = ℓ_ep;
    long delta_s = DELTA_S; // 1 seconds
    long U = MAX_GROUP_MEMBER;
    std::vector<std::string> G(I);

    for (size_t i = 0; i < I; ++i)
    {
        G[i] = "DGTOTP" + std::to_string(i);
        dgtotpVec[i].RASetup(k, G[i], U, T_s, T_e, delta_e, delta_s);
    }
    sk_ske = DGTOTP_PRF::createKey();
}

void sendConfKeysToAS(const std::vector<ConfKey> ConfKeys, SSL_CTX *client_ctx)
{
    struct sockaddr_in as_addr;
    memset(&as_addr, 0, sizeof(as_addr));
    as_addr.sin_family = AF_INET;
    as_addr.sin_port = htons(AS_PORT);
    inet_pton(AF_INET, SERVER_AS_IP, &as_addr.sin_addr);
    int as_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(as_sock, (sockaddr *)&as_addr, sizeof(as_addr)) < 0)
    {
        perror("Connect to AS failed");
        close(as_sock);
        return;
    }
    SSL *as_ssl = SSL_new(client_ctx);
    SSL_set_fd(as_ssl, as_sock);
    if (SSL_connect(as_ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
        SSL_free(as_ssl);
        close(as_sock);
        return;
    }

    std::string msg = "ConfKeys:";
    for (const auto &confKey : ConfKeys)
    {
        uint32_t sgid_net = htonl(confKey.SGId);
        msg.append((char *)&sgid_net, 4);
        msg.append((char *)confKey.key.data(), confKey.key.size());
    }

    // Send and wait for ack
    if (SSL_write(as_ssl, msg.c_str(), msg.size()) > 0)
    {
        printf("Sent subgroup shared keys to AS: %zu bytes\n", msg.size());
        char ack[8];
        int r = SSL_read(as_ssl, ack, sizeof(ack) - 1);
        if (r > 0)
        {
            ack[r] = '\0';
            printf("AS acknowledgment: %s\n", ack);
        }
    }

    SSL_free(as_ssl);
    close(as_sock);
}

int main()
{
    SSL_CTX *ctx, *ctx1;
    int client_sockfd, verifier_sockfd, client_fd, verifier_fd;
    struct sockaddr_in server_ra_addr, server_ra_addr1;

    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Generate RA certificate and key if they don't exist
    std::string key_file = "RA.key";
    std::string cert_file = "RA.crt";
    if (!fileExists(key_file) || !fileExists(cert_file))
    {
        std::cout << "RA certificate or key not found, generating..." << std::endl;
        if (!GenerateKeyAndCertificate(key_file, cert_file))
        {
            std::cerr << "Failed to generate RA certificate and key" << std::endl;
            return 1;
        }
        std::cout << "RA certificate and key generated successfully" << std::endl;
    }
    else
    {
        std::cout << "RA certificate and key already exist, skipping generation" << std::endl;
    }

    const long sharedStartTime = getCurrentTimeMillis();
    writeProtocolStartTimeMillis(sharedStartTime);
    std::cout << "Protocol start time written to "
              << getProtocolStartTimeFilePath() << ": "
              << sharedStartTime << std::endl;

    // Pre-initialize all subgroup-specific DGTOTP instances.
    std::vector<DGTOTP> dgtotpVec(SG_NUM);
    unsigned char *sk_ske;
    ConfKeyList ConfKeys;

    struct TAUX taux;
    taux.T_s = sharedStartTime;
    taux.E = EPOCH_COUNT;

    RASetup(SECURITY_PARAMETER_BITS, taux, DELTA_E, SG_NUM, dgtotpVec, sk_ske);

    long currentTime = getCurrentTimeMillis();
    std::cout << "current time: " << currentTime << std::endl;

    std::string memberId;
    int selectedSGId = -1;

    // Part1: Solve client registration and key distribution
    // Create SSL context for client-server One-Way TLS connection
    ctx = create_context();
    configure_server_auth_context(ctx);

    // Create TCP socket
    client_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&server_ra_addr, 0, sizeof(server_ra_addr));
    server_ra_addr.sin_family = AF_INET;
    server_ra_addr.sin_port = htons(CLIENT_PORT);
    server_ra_addr.sin_addr.s_addr = INADDR_ANY;

    bind(client_sockfd, (struct sockaddr *)&server_ra_addr, sizeof(server_ra_addr));
    listen(client_sockfd, 5);

    printf("TLS 1.3 Server listening on port %d\n", CLIENT_PORT);

    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
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
                ConfKey ConfKeyID;
                ConfKeyID.SGId = selectedSGId;
                ConfKeyID.key.resize(KEY_LENGTH_BYTES);
                unsigned char rv[KEY_LENGTH_BYTES];
                RAND_bytes(rv, KEY_LENGTH_BYTES);
                std::string msg = "SK" + bytesToHex(rv, KEY_LENGTH_BYTES);
                // ConfKeyID.key = F1(sk_ske, "SK"||rv);
                prf1(ConfKeyID.key.data(), ConfKeyID.key.size(),
                     sk_ske, KEY_LENGTH_BYTES,
                     reinterpret_cast<const unsigned char *>(msg.c_str()), msg.length());
                ConfKeys.push_back(ConfKeyID);

                std::cout << "RA shared key of the join member: ";
                printBytes(joinReceipt.shared_key.data(), joinReceipt.shared_key.size());
                std::cout << std::endl;
                std::cout << "Alpha ID of the join member: ";
                printBytes(joinReceipt.alpha_bytes.data(), joinReceipt.alpha_bytes.size());
                std::cout << std::endl;
                std::cout << "AS shared key of the join member: ";
                printBytes(ConfKeyID.key.data(), ConfKeyID.key.size());
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
                buffer.insert(buffer.end(), ConfKeyID.key.begin(), ConfKeyID.key.end());

                // Send actual data
                SSL_write(client_ssl, buffer.data(), buffer.size());
                printf("Sent RA shared key, alpha, and AS shared key to member\n");
            }
        }
    }
    SSL_shutdown(client_ssl);
    SSL_free(client_ssl);
    close(client_fd);
    SSL_CTX_free(ctx);
    close(client_sockfd);

    // Part2: Simulate group member joining
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
            ConfKey new_ConfKeyID;
            new_ConfKeyID.SGId = new_SGId;
            new_ConfKeyID.key.resize(KEY_LENGTH_BYTES);
            unsigned char new_rv[KEY_LENGTH_BYTES];
            RAND_bytes(new_rv, KEY_LENGTH_BYTES);
            std::string new_msg = "SK" + bytesToHex(new_rv, KEY_LENGTH_BYTES);
            // new_ConfKeyID.key = F1(sk_ske, "SK"||rv);
            prf1(new_ConfKeyID.key.data(), new_ConfKeyID.key.size(),
                 sk_ske, KEY_LENGTH_BYTES,
                 reinterpret_cast<const unsigned char *>(new_msg.c_str()), new_msg.length());
            ConfKeys.push_back(new_ConfKeyID);
        }
    }

    // Part3: Send all subgroup shared keys to AS
    SSL_CTX *client_ctx = create_client_context();
    if (!ConfKeys.empty())
    {
        sendConfKeysToAS(ConfKeys, client_ctx);
    }
    SSL_CTX_free(client_ctx);

    // Part4: Create SSL context for verifier-server Mutual Auth TLS connection
    ctx1 = create_context();
    configure_mutual_auth_context(ctx1);

    // Create TCP socket
    verifier_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&server_ra_addr1, 0, sizeof(server_ra_addr1));
    server_ra_addr1.sin_family = AF_INET;
    server_ra_addr1.sin_port = htons(VERIFIER_PW_PORT);
    server_ra_addr1.sin_addr.s_addr = INADDR_ANY;

    bind(verifier_sockfd, (struct sockaddr *)&server_ra_addr1, sizeof(server_ra_addr1));
    listen(verifier_sockfd, 5);

    printf("TLS 1.3 RA_Server listening on port %d\n", VERIFIER_PW_PORT);

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
                const size_t pw_prefix_len = strlen("PW:");

                if (bytes >= static_cast<int>(pw_prefix_len) &&
                    memcmp(buf, "PW:", pw_prefix_len) == 0)
                {
                    printf("Received password pw from verifier\n");
                    std::string received_data(buf, bytes);
                    // Remove "PW:" prefix
                    std::string pw_data = received_data.substr(3);

                    // Extract password and SGId
                    DGTOTP::Password password;
                    int SGId = 0;
                    if (pw_data.length() >= 32 + 32 + 20 + SG_LENGTH_BYTES)
                    {
                        password.totp_password = pw_data.substr(0, 32);
                        password.collision_randomness = pw_data.substr(32, 32);
                        password.identity_ciphertext = pw_data.substr(32 + 32, 20);
                        SGId = static_cast<unsigned char>(pw_data[32 + 32 + 20]);
                        printf("Extracted SGId: %d\n", SGId);
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
                    dgtotpVec[SGId].refreshPublishedState(verifyTime);
                    int verifyResult = dgtotpVec[SGId].Verify(password, verifyTime);
                    std::cout << "Verify result for the correct password and verify epoch: " << (verifyResult == 1 ? "success" : "failure") << std::endl;
                    std::cout << std::endl;

                    std::string openResult = dgtotpVec[SGId].Open(password, verifyTime);
                    std::cout << "Open ID for the correct password and verify epoch: " << openResult << std::endl;
                    std::cout << std::endl;

                    std::string response = "Verify result:";
                    if (verifyResult == 1)
                        response += "success";
                    else
                        response += "failure";
                    SSL_write(verifier_ssl, response.c_str(), response.length());
                    keep_connection = false;
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
    free(sk_ske);

    return 0;
}