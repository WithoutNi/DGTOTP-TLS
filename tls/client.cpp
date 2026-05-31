#include <iostream>
#include <cstring>
#include <string>
#include <vector>
#include <ctime>
#include <chrono>
#include <cstdint>

#include <unistd.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "DGTOTP.h"
#include "DGTOTP_PRF.h"
#include "util.h"
#include "../test/cycles.h"

#define VERIFIER_IP "127.0.0.1"
#define VERIFIER_PORT 4434
#define SERVER_PORT 4435
#define BUFFER_SIZE 1024

// Global variables to store Finished message
static unsigned char fin_msg[BUFFER_SIZE];
static size_t fin_msg_len = 0;

struct SSLIOCounter
{
    uint64_t read;
    uint64_t written;
};

SSLIOCounter GetSSLIOCounter(SSL *ssl)
{
    BIO *rbio = SSL_get_rbio(ssl);
    BIO *wbio = SSL_get_wbio(ssl);

    return {
        rbio ? BIO_number_read(rbio) : 0,
        wbio ? BIO_number_written(wbio) : 0};
}

void PrintSSLIOStats(const std::string &label,
                     const SSLIOCounter &before,
                     const SSLIOCounter &after)
{
    const uint64_t sent = after.written - before.written;
    const uint64_t received = after.read - before.read;

    std::cout << "[" << label << "] communication overhead: sent "
              << std::dec << sent << " bytes, received "
              << std::dec << received << " bytes, total "
              << std::dec << sent + received << " bytes" << std::endl;
}

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
    for (int i = 0; i < tag_len; i += KEY_LENGTH_BYTES)
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

SSL_CTX *create_context()
{
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        perror("SSL_CTX_new failed");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

int main()
{
    SSL_CTX *ctx, *ctx1;
    int server_sockfd, verifier_sockfd;
    struct sockaddr_in server_addr, verifier_addr;
    const long sharedStartTime = readProtocolStartTimeMillis();
    std::cout << "Protocol start time read from "
              << getProtocolStartTimeFilePath() << ": "
              << sharedStartTime << std::endl;
    std::string memberId;
    DGTOTP dgtotp;
    DGTOTP::JoinReceipt joinReceipt;
    const int securityParameter = SECURITY_PARAMETER_BITS;
    const int groupMemberCount = 10;
    const int verificationPeriod = 300000;
    const int passwordGenerationPeriod = 5000;
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
    ctx = create_context();
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    // Create TCP connection (connect to server)
    server_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, VERIFIER_IP, &server_addr.sin_addr);

    if (connect(server_sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)))
    {
        perror("Failed to connect to server");
        exit(EXIT_FAILURE);
    }

    // Create SSL connection
    SSL *server_ssl = SSL_new(ctx);
    SSL_set_fd(server_ssl, server_sockfd);

    // Perform TLS handshake
    if (SSL_connect(server_ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
    }
    else
    {
        printf("Connected to server with %s\n", SSL_get_cipher(server_ssl));

        std::cout << "Computed SGId: " << SGId << std::endl;
        std::cout << "Client group name: " << groupName << std::endl;
        std::string message = "memberId:" + memberId;

        // Send memberId
        int bytes_sent = SSL_write(server_ssl, message.c_str(), message.size());
        if (bytes_sent > 0)
        {
            std::cout << message << std::endl;
        }
        else
        {
            std::cerr << "Failed to send data" << std::endl;
        }
        // Maintain connection and continuously receive responses
        unsigned char server_response[BUFFER_SIZE];
        bool keep_connection = true;
        while (keep_connection)
        {
            size_t server_response_len = SSL_read(server_ssl, server_response, sizeof(server_response) - 1);
            if (server_response_len > 0)
            {
                if (server_response_len < KEY_LENGTH_BYTES + 4 + KEY_LENGTH_BYTES)
                {
                    throw std::runtime_error("Server join receipt is too short");
                }

                printf("Received from server: %zu bytes\n", server_response_len);
                server_response[server_response_len] = '\0';
                printf("server response: \n");
                for (size_t i = 0; i < server_response_len; i++)
                {
                    printf("%02X ", server_response[i]);
                    if ((i + 1) % 16 == 0)
                        printf("\n");
                }
                printf("\n");
                joinReceipt.shared_key.assign(server_response, server_response + KEY_LENGTH_BYTES);
                joinReceipt.alpha_bytes.assign(server_response + KEY_LENGTH_BYTES, server_response + 20);
                memcpy(shared_key_RA, joinReceipt.shared_key.data(), sizeof(shared_key_RA));
                memcpy(alpha_bytes, joinReceipt.alpha_bytes.data(), sizeof(alpha_bytes));
                memcpy(shared_key_AS, server_response + 20, sizeof(shared_key_AS));
            }
            else if (server_response_len == 0)
            {
                // Close connection
                printf("server closed the connection\n");
                keep_connection = false;
            }
            else
            {
                int err = SSL_get_error(server_ssl, server_response_len);
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
    SSL_shutdown(server_ssl);
    SSL_free(server_ssl);
    SSL_CTX_free(ctx);
    close(server_sockfd);

    std::cout << std::endl;
    std::cout << "********************************" << std::endl;
    std::cout << std::endl;

    // Calculate DGTOTP password and commitment
    DGTOTP::Password password;
    pw_CM commitment;
    std::string SG;

    // TLS connection with verifier
    // Create SSL context
    ctx1 = create_context();
    SSL_CTX_set_min_proto_version(ctx1, TLS1_3_VERSION);

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
    const SSLIOCounter verifier_handshake_io_before = GetSSLIOCounter(verifier_ssl);
    const auto verifier_handshake_start = std::chrono::steady_clock::now();
    const unsigned long long verifier_handshake_cycles_before = cpucycles();

    if (SSL_connect(verifier_ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
    }
    else
    {
        const unsigned long long verifier_handshake_cycles_after = cpucycles();
        const auto verifier_handshake_end = std::chrono::steady_clock::now();

        const auto verifier_handshake_duration_us =
            std::chrono::duration_cast<std::chrono::microseconds>(
                verifier_handshake_end - verifier_handshake_start)
                .count();
        const SSLIOCounter verifier_handshake_io_after = GetSSLIOCounter(verifier_ssl);

        std::cout << "[TLS Handshake Stats] computation time: "
                  << verifier_handshake_duration_us << " us" << std::endl;

        std::cout << "[TLS Handshake Stats] cycles: "
                  << verifier_handshake_cycles_after - verifier_handshake_cycles_before
                  << std::endl;
        PrintSSLIOStats("TLS Handshake Stats", verifier_handshake_io_before, verifier_handshake_io_after);
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
        // message=COMMITMENT+SG
        std::string Com = commitment.UCM + commitment.SCM + SG;
        std::string message = "MSG:" + Com;

        // Send commitment and related information
        const SSLIOCounter com_io_before = GetSSLIOCounter(verifier_ssl);
        const auto send_com_start = std::chrono::steady_clock::now();
        int bytes_sent = SSL_write(verifier_ssl, message.c_str(), message.length());
        if (bytes_sent > 0)
        {
            const auto send_com_end = std::chrono::steady_clock::now();
            const auto send_com_duration_us =
                std::chrono::duration_cast<std::chrono::microseconds>(send_com_end - send_com_start).count();
            const SSLIOCounter com_io_after = GetSSLIOCounter(verifier_ssl);
            std::cout << "[Send Com] computation time: " << send_com_duration_us << " us" << std::endl;
            PrintSSLIOStats("Write com Stats", com_io_before, com_io_after);
            std::cout << "Successfully sent commitment data: " << bytes_sent << " bytes" << std::endl;
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
            const SSLIOCounter tag_io_before = GetSSLIOCounter(verifier_ssl);
            int bytes = SSL_read(verifier_ssl, buf, sizeof(buf) - 1);
            if (bytes > 0)
            {
                const SSLIOCounter tag_io_after = GetSSLIOCounter(verifier_ssl);
                PrintSSLIOStats("Read tag Stats", tag_io_before, tag_io_after);
                buf[bytes] = '\0';
                printf("Verifier response: \n");
                for (size_t i = 0; i < bytes; i++)
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
                    const SSLIOCounter pw_io_before = GetSSLIOCounter(verifier_ssl);
                    int pw_len = SSL_write(verifier_ssl, pw.c_str(), pw.length());
                    const SSLIOCounter pw_io_after = GetSSLIOCounter(verifier_ssl);
                    PrintSSLIOStats("Write pw Stats", pw_io_before, pw_io_after);
                    std::cout << "Successfully sent password data: " << pw_len << " bytes" << std::endl;
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
