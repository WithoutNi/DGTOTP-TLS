#include <iostream>
#include <cstring>
#include <string>
#include <vector>
#include <ctime>

#include <unistd.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "DGTOTP.h"
#include "DGTOTP_PRF.h"
#ifndef UTIL_H
#include "util.h"
#endif

#define VERIFIER_IP "127.0.0.1"
#define SERVER_RA_IP "127.0.0.1"
#define VERIFIER_PORT 4434
#define SERVER_RA_PORT 4435
#define BUFFER_SIZE 1024

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

// Global variables to store Finished message
static unsigned char fin_msg[BUFFER_SIZE];
static size_t fin_msg_len = 0;

int TagCheck(unsigned char ki[], int current_epoch_j, std::string SG, pw_CM commitment, const unsigned char *tags, size_t tag_len)
{
    unsigned char kij[KEY_LENGTH_BYTES];
    std::string kg_input = std::string("KG") + std::to_string(current_epoch_j);
    // kij=F1(ki,"KG"||j)
    prf1(kij, KEY_LENGTH_BYTES, ki, KEY_LENGTH_BYTES,
         reinterpret_cast<const unsigned char *>(kg_input.data()), kg_input.size());

    unsigned char tag_key[KEY_LENGTH_BYTES];
    std::string kt_input = std::string("KT") + SG;
    // k_tag=F1(kij,"KT"||SG)
    prf1(tag_key, KEY_LENGTH_BYTES, kij, KEY_LENGTH_BYTES,
         reinterpret_cast<const unsigned char *>(kt_input.data()), kt_input.size());

    unsigned char tag[KEY_LENGTH_BYTES];
    std::string tag_input = std::string("Tag") + commitment.UCM + commitment.SCM;
    // tag=F1(k_tag,"Tag"||CM)
    prf1(tag, KEY_LENGTH_BYTES, tag_key, KEY_LENGTH_BYTES,
         reinterpret_cast<const unsigned char *>(tag_input.data()), tag_input.size());
    std::cout << "tag: ";
    printBytes(tag, KEY_LENGTH_BYTES);
    std::cout << std::endl;
    // compare method should compare every KEY_LENGTH_BYTES bytes in tags
    for (size_t i = 0; i + KEY_LENGTH_BYTES <= tag_len; i += KEY_LENGTH_BYTES)
    {
        if (memcmp(tags + i, tag, KEY_LENGTH_BYTES) == 0)
        {
            return 1;
        }
    }
    return 0;
}

void msg_callback(int write_p, int version, int content_type,
                  const void *buf, size_t len, SSL *ssl, void *arg)
{
    if (content_type != SSL3_RT_HANDSHAKE)
        return;
    (void)version;
    (void)ssl;
    (void)arg;
    const unsigned char *p = (unsigned char *)buf;
    if (len > 0 && p[0] == SSL3_MT_FINISHED && !write_p)
    {
        printf("\n--- Received Finished Message (%zu bytes) ---\n", len);

        // Save Finished message
        memcpy(fin_msg, buf, len);
        fin_msg_len = len;

        // Print message
        for (size_t i = 0; i < len; i++)
        {
            printf("%02X ", fin_msg[i]);
            if ((i + 1) % 16 == 0)
                printf("\n");
        }
        printf("\n");
    }
}

SSL_CTX *create_client_context()
{
    int iRet = 0;
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    iRet = (ctx != NULL) ? 1 : 0;
    CHECK_SSL_CTX(iRet, "SSL_CTX_new");

    iRet = SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    CHECK_SSL_CTX(iRet, "SSL_CTX_set_min_proto_version");

    // Verify server certificate using CA
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    iRet = SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL);
    CHECK_SSL_CTX(iRet, "SSL_CTX_load_verify_locations");

    return ctx;
}

int main()
{
    SSL_CTX *ctx, *ctx1;
    int ra_sockfd, verifier_sockfd;
    struct sockaddr_in server_ra_addr, verifier_addr;
    const long sharedStartTime = readProtocolStartTimeMillis();
    std::cout << "Protocol start time read from "
              << getProtocolStartTimeFilePath() << ": "
              << sharedStartTime << std::endl;
    std::string memberId;
    DGTOTP dgtotp;
    DGTOTP::JoinReceipt joinReceipt;
    const int securityParameter = SECURITY_PARAMETER_BITS;
    const int groupMemberCount = MAX_GROUP_MEMBER;
    const int verificationPeriod = DELTA_E;
    const int passwordGenerationPeriod = DELTA_S;
    const long endTime = sharedStartTime + EPOCH_COUNT * verificationPeriod;

    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Prepare memberId first, then derive the subgroup-specific group name.
    unsigned char ID[ID_LENGTH_BYTES];
    RAND_bytes(ID, ID_LENGTH_BYTES);
    memberId = bytesToHex(ID, ID_LENGTH_BYTES);

    int SGId = SGMap(k_sg, sizeof(k_sg), memberId);
    const std::string groupName = "DGTOTP" + std::to_string(SGId);
    dgtotp.ImportParameters(securityParameter, groupName, groupMemberCount, sharedStartTime, endTime,
                            verificationPeriod, passwordGenerationPeriod);
    dgtotp.PInit(memberId);

    unsigned char shared_key_RA[KEY_LENGTH_BYTES] = {0};
    unsigned char shared_key_AS[KEY_LENGTH_BYTES] = {0};
    unsigned char alpha_bytes[4] = {0};

    // TLS connection with server
    // Create SSL context
    ctx = create_client_context();

    // Create TCP connection (connect to server)
    ra_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&server_ra_addr, 0, sizeof(server_ra_addr));
    server_ra_addr.sin_family = AF_INET;
    server_ra_addr.sin_port = htons(SERVER_RA_PORT);
    inet_pton(AF_INET, SERVER_RA_IP, &server_ra_addr.sin_addr);

    if (connect(ra_sockfd, (struct sockaddr *)&server_ra_addr, sizeof(server_ra_addr)))
    {
        perror("Failed to connect to server");
        exit(EXIT_FAILURE);
    }

    // Create SSL connection
    SSL *ra_ssl = SSL_new(ctx);
    SSL_set_fd(ra_ssl, ra_sockfd);

    // Perform TLS handshake
    if (SSL_connect(ra_ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
    }
    else
    {
        printf("Connected to server with %s\n", SSL_get_cipher(ra_ssl));

        std::cout << "Computed SGId: " << SGId << std::endl;
        std::cout << "Client group name: " << groupName << std::endl;
        std::string message = "memberId:" + memberId;

        // Send memberId
        int bytes_sent = SSL_write(ra_ssl, message.c_str(), message.size());
        if (bytes_sent > 0)
        {
            std::cout << message << std::endl;
        }
        else
        {
            std::cerr << "Failed to send data" << std::endl;
        }
        // Maintain connection and continuously receive responses
        unsigned char ra_response[BUFFER_SIZE];
        bool keep_connection = true;
        while (keep_connection)
        {
            int ra_response_len = SSL_read(ra_ssl, ra_response, sizeof(ra_response) - 1);
            if (ra_response_len > 0)
            {
                if (ra_response_len < KEY_LENGTH_BYTES + 4 + KEY_LENGTH_BYTES)
                {
                    throw std::runtime_error("Server join receipt is too short");
                }

                printf("Received from server: %d bytes\n", ra_response_len);
                ra_response[ra_response_len] = '\0';
                printf("server response: \n");
                for (int i = 0; i < ra_response_len; i++)
                {
                    printf("%02X ", ra_response[i]);
                    if ((i + 1) % 16 == 0)
                        printf("\n");
                }
                printf("\n");
                joinReceipt.shared_key.assign(ra_response, ra_response + KEY_LENGTH_BYTES);
                joinReceipt.alpha_bytes.assign(ra_response + KEY_LENGTH_BYTES, ra_response + 20);
                memcpy(shared_key_RA, joinReceipt.shared_key.data(), sizeof(shared_key_RA));
                memcpy(alpha_bytes, joinReceipt.alpha_bytes.data(), sizeof(alpha_bytes));
                memcpy(shared_key_AS, ra_response + 20, sizeof(shared_key_AS));
            }
            else if (ra_response_len == 0)
            {
                // Close connection
                printf("server closed the connection\n");
                keep_connection = false;
            }
            else
            {
                int err = SSL_get_error(ra_ssl, ra_response_len);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                {
                    // Continue waiting for data
                    usleep(100000); // Wait 100ms
                    continue;
                }
                else
                {
                    printf("SSL read error: %d\n", err);
                    keep_connection = false;
                }
            }
        }
    }
    SSL_shutdown(ra_ssl);
    SSL_free(ra_ssl);
    SSL_CTX_free(ctx);
    close(ra_sockfd);

    std::cout << std::endl;
    std::cout << "********************************" << std::endl;
    std::cout << std::endl;

    // Calculate DGTOTP password and commitment
    DGTOTP::Password password;
    pw_CM commitment;
    std::string SG;

    // TLS connection with verifier
    // Create SSL context
    ctx1 = create_client_context();

    // Create TCP connection (connect to Verifier)
    verifier_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&verifier_addr, 0, sizeof(verifier_addr));
    verifier_addr.sin_family = AF_INET;
    verifier_addr.sin_port = htons(VERIFIER_PORT);
    inet_pton(AF_INET, VERIFIER_IP, &verifier_addr.sin_addr);

    if (connect(verifier_sockfd, (struct sockaddr *)&verifier_addr, sizeof(verifier_addr)))
    {
        perror("Failed to connect to verifier");
        exit(EXIT_FAILURE);
    }

    // Create SSL connection
    SSL *verifier_ssl = SSL_new(ctx1);
    SSL_set_fd(verifier_ssl, verifier_sockfd);

    // Set message callback
    SSL_set_msg_callback(verifier_ssl, msg_callback);
    SSL_set_msg_callback_arg(verifier_ssl, NULL);

    // Perform TLS handshake
    if (SSL_connect(verifier_ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
    }
    else
    {
        printf("Connected to verifier with %s\n", SSL_get_cipher(verifier_ssl));

        // Prepare data to send
        try
        {
            const long protocolTime = getCurrentTimeMillis();
            dgtotp.ImportJoinReceipt(memberId, joinReceipt);
            std::string secretSeed = dgtotp.GetSD(memberId, protocolTime);
            password = dgtotp.PwGen(memberId, secretSeed, protocolTime);

            int alpha_ID = Parameter::bytesToInt(alpha_bytes);
            printf("alpha_ID: %d\n", alpha_ID);
            printf("fin_msg:%ld bytes\n", fin_msg_len);
            for (size_t i = 0; i < fin_msg_len; i++)
            {
                printf("%02X ", fin_msg[i]);
                if ((i + 1) % 16 == 0)
                    printf("\n");
            }
            printf("\n");
            SG = std::string(1, static_cast<char>(SGId));
            commitment = CMGen(password.toVector(), fin_msg, fin_msg_len);

            std::cout << "=== Calculation Complete ===" << std::endl;
            std::cout << "TOTP Password: " << string_to_hex(password.totp_password) << std::endl;
            std::cout << "Chameleon Hash Collision: " << string_to_hex(password.collision_randomness) << std::endl;
            std::cout << "Identity Ciphertext: " << string_to_hex(password.identity_ciphertext) << std::endl;
            std::cout << "UCM: " << string_to_hex(commitment.UCM) << std::endl;
            std::cout << "SCM: " << string_to_hex(commitment.SCM) << std::endl;
            std::cout << "==========================" << std::endl;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Error calculating password: " << e.what() << std::endl;
            return 1;
        }
        // message PURec=COMMITMENT+SG
        std::string PURec = commitment.UCM + commitment.SCM + SG;
        std::string message = "PURec:" + PURec;

        // Send commitment and related information
        int bytes_sent = SSL_write(verifier_ssl, message.c_str(), message.length());
        if (bytes_sent > 0)
        {
            std::cout << "Successfully sent commitment data: " << std::dec << bytes_sent << " bytes" << std::endl;
        }
        else
        {
            std::cerr << "Failed to send data" << std::endl;
        }

        // Maintain connection and continuously receive responses
        unsigned char buf[BUFFER_SIZE];
        bool keep_connection = true;

        while (keep_connection)
        {
            int bytes = SSL_read(verifier_ssl, buf, sizeof(buf) - 1);
            if (bytes > 0)
            {
                buf[bytes] = '\0';
                printf("Verifier response: \n");
                for (int i = 0; i < bytes; i++)
                {
                    printf("%02X ", buf[i]);
                    if ((i + 1) % 16 == 0)
                        printf("\n");
                }
                printf("\n");
                // verify tag
                long time1 = getCurrentTimeMillis();
                const Parameter &params = dgtotp.getParameter();
                int current_epoch_j = (int)((time1 - params.getStartTime()) / params.getDeltaE());
                std::cout << "In Client, current_epoch_j=" << std::dec << current_epoch_j << std::endl;

                int result = TagCheck(shared_key_AS, current_epoch_j, SG, commitment, buf, bytes);
                if (result == 1)
                {
                    printf("Verfiy tag success,sent DGTOTP password\n");
                    std::string pw = "PW:" + password.totp_password +
                                     password.collision_randomness +
                                     password.identity_ciphertext;
                    int pw_len = SSL_write(verifier_ssl, pw.c_str(), pw.length());
                    std::cout << "Successfully sent password data: " << std::dec << pw_len << " bytes" << std::endl;
                }

                // close the connection
                keep_connection = false;
            }
            else if (bytes == 0)
            {
                printf("Verifier closed the connection\n");
                keep_connection = false;
            }
            else
            {
                int err = SSL_get_error(verifier_ssl, bytes);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                {
                    // Continue waiting for data
                    usleep(10); // Wait 100ms
                    continue;
                }
                else
                {
                    printf("SSL read error: %d\n", err);
                    keep_connection = false;
                }
            }
        }
    }

    SSL_shutdown(verifier_ssl);
    SSL_free(verifier_ssl);
    SSL_CTX_free(ctx1);
    close(verifier_sockfd);

    return 0;
}
