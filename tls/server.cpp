#include <iostream>
#include <cstring>
#include <string>
#include <vector>
#include <ctime>
#include <chrono>
#include <unistd.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "Parameter.h"
#include "ChameleonHash.h"
#include "MerkleTrees.h"
#include "TOTP.h"
#include "Member.h"
#include "RA.h"
#include "Verifier.h"
#include "DGTOTP_PRF.h"
#include "util.h"

#define VERIFIER_PORT 4433
#define CLIENT_PORT 4435
#define BUFFER_SIZE 1024

static unsigned char received_msg[BUFFER_SIZE];
static size_t received_msg_len = 0;

// Helper function: get current timestamp (milliseconds)
long getCurrentTimeMillis()
{
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
}

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
std::vector<std::vector<unsigned char>> MacGen(
    RA &ra,
    Parameter &params,
    const unsigned char *ki,
    size_t ki_len,
    const unsigned char *received_msg,
    size_t received_msg_len)
{
    // Add boundary check
    if (received_msg_len < 2 * 64 + 2 * SG_LENGTH)
    {
        throw std::runtime_error("Received message too short");
    }

    if (ki == nullptr || ki_len == 0)
    {
        throw std::runtime_error("Shared key is empty");
    }

    unsigned char kij[16];
    unsigned char SG_hex[2 * SG_LENGTH];

    // Safe copy
    memcpy(SG_hex, received_msg + 2 * 64, 2 * SG_LENGTH);
    std::vector<unsigned char> SG_vec = HexToBytes(SG_hex, 2 * SG_LENGTH);
    printf("sub group identity=");
    for (size_t i = 0; i < SG_LENGTH; i++)
    {
        printf("%02X ", SG_vec[i]);
    }
    printf("\n");

    unsigned char k_mac[16];
    unsigned char mac[16];
    std::vector<unsigned char> mac_vector;
    std::vector<std::vector<unsigned char>> mac_collection;
    long time1 = getCurrentTimeMillis();
    int current_epoch_j = (int)((time1 - params.getStartTime()) / params.getDeltaE());
    prf(kij, 16, const_cast<unsigned char *>(ki), ki_len, current_epoch_j);
    prf1(k_mac, 16, kij, 16, SG_hex, 2 * SG_LENGTH);
    prf1(mac, 16, k_mac, 16, received_msg, received_msg_len);

    std::cout << "mac: ";
    printBytes(mac, 16);
    std::cout << std::endl;

    mac_vector.assign(mac, mac + 16);
    mac_collection.push_back(mac_vector);

    printf("match mac number: %ld\n", mac_collection.size());
    return mac_collection;
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

    // Set security parameter
    int k = 128;
    const long sharedStartTime = getSharedProtocolStartTimeMillis();
    const size_t subgroupCount = SG_NUM;

    // Pre-initialize all subgroup-specific params and RA instances.
    std::vector<Parameter> paramsVec;
    std::vector<RA> raVec;
    paramsVec.reserve(subgroupCount);
    raVec.reserve(subgroupCount);

    for (size_t i = 0; i < subgroupCount; ++i)
    {
        const std::string groupName = "DGTOTP" + std::to_string(i);

        Parameter params;
        params.init(groupName, sharedStartTime);

        RA ra;
        ra.RASetup(k, params.getG(), params.getU(),
                   params.getStartTime(), params.getEndTime(),
                   params.getDeltaE(), params.getDeltaS());

        paramsVec.push_back(params);
        raVec.push_back(ra);

        // std::cout << "Initialized subgroup " << i
        //           << " with group name " << groupName << std::endl;
        // std::cout << "RA group public key: " << ra.getGpk() << std::endl;
    }

    long currentTime = getCurrentTimeMillis();
    std::cout << "current time: " << currentTime << std::endl;

    // Create SSL context
    ctx = create_context();
    configure_context(ctx);
    unsigned char memberId_char[16];

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
    unsigned char alpha[4];
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

                selectedSGId = SGIdGen(k_sg, sizeof(k_sg), memberId);
                if (selectedSGId < 0 || static_cast<size_t>(selectedSGId) >= subgroupCount)
                {
                    throw std::runtime_error("Computed SGId out of range");
                }

                std::cout << "Selected SGId: " << selectedSGId << std::endl;
                std::cout << "Selected group name: " << paramsVec[selectedSGId].getG() << std::endl;

                const long joinTime = getCurrentTimeMillis();
                std::vector<unsigned char *> Ax = raVec[selectedSGId].Join(nullptr, memberId, joinTime);
                size_t alphaID = bytesToInt(Ax[1]);
                RA::AS::getInstance().storeKey(alphaID, Ax[0], 16);
                std::cout << "Ks of the join member: ";
                printBytes(Ax[0], 16);
                std::cout << std::endl;
                std::cout << "Alpha ID of the join member: ";
                printBytes(Ax[1], 4);
                memcpy(alpha, Ax[1], 4);
                std::cout << std::endl;

                size_t total_length = 16 + 4; // Adjust according to your actual data size

                // Create buffer and copy data
                std::vector<unsigned char> buffer;
                buffer.reserve(total_length);

                // Copy first pointer data (16 bytes)
                buffer.insert(buffer.end(), Ax[0], Ax[0] + 16);

                // Copy second pointer data (32 bytes)
                buffer.insert(buffer.end(), Ax[1], Ax[1] + 4);

                // Send actual data
                SSL_write(client_ssl, buffer.data(), buffer.size());
                printf("Sent share key to member\n");
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
    unsigned char ki_hex[32];
    unsigned char ki[16];
    unsigned char SG_hex[2 * SG_LENGTH];

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

                // Check if it's MSG content
                if (strstr(buf, "MSG:"))
                {
                    printf("Received MSG content from verifier\n");

                    // extract ki
                    const unsigned char *content = (const unsigned char *)(buf + strlen("MSG:"));
                    memcpy(ki_hex, content, 32);
                    std::vector<unsigned char> ki_vec = HexToBytes(ki_hex, 32);
                    memcpy(ki, ki_vec.data(), 16);

                    // extract commiment+SG from received message (MSG:ki+commiment+SG)
                    content = content + 32;
                    size_t content_len = bytes - strlen("MSG:") - 32;

                    // Save commiment+SG
                    memcpy(received_msg, content, content_len);
                    received_msg_len = content_len;

                    content = content + 2 * 64;
                    content_len = bytes - strlen("MSG:") - 32 - 2 * 64;
                    memcpy(SG_hex, content, content_len);

                    // Print original message
                    printf("Original Received message (%zu bytes):\n", received_msg_len);
                    for (size_t i = 0; i < received_msg_len; i++)
                    {
                        printf("%c", received_msg[i]);
                    }
                    printf("\n");

                    std::vector<std::vector<unsigned char>> macs = MacGen(raVec[selectedSGId], paramsVec[selectedSGId], ki, sizeof(ki), received_msg, received_msg_len);
                    // Calculate total bytes
                    size_t total_size = 0;
                    for (const auto &mac : macs)
                    {
                        total_size += mac.size();
                    }

                    // Create continuous buffer
                    std::vector<unsigned char> buffer;
                    buffer.reserve(total_size);

                    // Concatenate all MACs
                    for (const auto &mac : macs)
                    {
                        buffer.insert(buffer.end(), mac.begin(), mac.end());
                    }

                    // Send data
                    SSL_write(verifier_ssl, buffer.data(), buffer.size());
                    // Send MAC
                    printf("Sent compute mac to verifier\n");
                    printf("\n");
                }
                else if (strstr(buf, "PW:"))
                {
                    printf("Received password pw from verifier\n");
                    std::string received_data(buf, bytes);
                    // remove PW:
                    std::string pw_data = received_data.substr(3);

                    std::vector<std::string> password;

                    // Extract using known lengths (ensure correct length)
                    if (pw_data.length() >= 64 + 32 + 20)
                    {
                        password.push_back(pw_data.substr(0, 64));       // TOTP Password
                        password.push_back(pw_data.substr(64, 32));      // Chameleon Hash
                        password.push_back(pw_data.substr(64 + 32, 20)); // Identity Ciphertext
                    }
                    else
                    {
                        throw std::runtime_error("Received password data too short");
                    }

                    std::cout << "TOTP Password: " << password[0] << std::endl;
                    std::cout << "Chameleon Hash: " << string_to_hex(password[1]) << std::endl;
                    std::cout << "Identity Ciphertext: " << string_to_hex(password[2]) << std::endl;

                    // Verify DGTOTP password using a fresh timestamp and current epoch metadata.
                    const long verifyTime = getCurrentTimeMillis();

                    raVec[selectedSGId].GMUpdate(verifyTime, paramsVec[selectedSGId]);
                    Verifier verifier;
                    int verifyResult = verifier.Verify(password, verifyTime, paramsVec[selectedSGId]);
                    std::cout << "Verify result for the correct password and verify epoch: " << (verifyResult == 1 ? "success" : "failure") << std::endl;
                    std::cout << std::endl;

                    // open ID
                    //  std::string openResult = ra.Open(password, currentTime);
                    //  std::cout << "Open ID for the correct password and verify epoch: " << openResult << std::endl;
                    //  std::cout << std::endl;

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

    // Clean up resources
    for (RA &ra : raVec)
    {
        ra.cleanup();
    }
    for (Parameter &params : paramsVec)
    {
        params.cleanup();
    }

    return 0;
}
