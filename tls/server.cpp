#include <iostream>
#include <cstring>
#include <string>
#include <vector>
#include <ctime>
#include <chrono>
#include <random>
#include <algorithm>

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

std::string SGGen(unsigned char ki[], size_t key_len, size_t alpha_ID, Parameter &params)
{
    long time = getCurrentTimeMillis();
    int j = (int)((time - params.getStartTime()) / params.getDeltaE());

    unsigned char kij[32];
    // index=current epoch index
    prf(kij, key_len, ki, key_len, j);

    unsigned char SG_bytes[SG_LENGTH];
    // index= user index
    prf(SG_bytes, SG_LENGTH, kij, key_len, alpha_ID);

    // Convert unsigned char array to hexadecimal string
    return bytesToHex(SG_bytes, SG_LENGTH, true);
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
    const unsigned char *received_msg,
    size_t received_msg_len)
{
    // Add boundary check
    if (received_msg_len < 2 * 64 + 2 * SG_LENGTH)
    {
        throw std::runtime_error("Received message too short");
    }

    unsigned char ID[ID_LENGTH];
    std::string memberId;
    long currentTime = getCurrentTimeMillis();
    std::vector<unsigned char *> Ax;
    size_t alpha_ID;
    std::vector<unsigned char> shared_key;
    unsigned char kij[16];
    int current_epoch_j = (int)((currentTime - params.getStartTime()) / params.getDeltaE());
    std::string SG;
    unsigned char SG_hex[2 * SG_LENGTH];
    // Get shared key store instance
    auto &SKeys = RA::AS::getInstance();

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
    int Z = 0;
    int count = ra.getU() - 1;
    const auto &IDLG = ra.getIDLG();
    for (int j = 0; j < count; j++)
    {
        // 1. Generate random ID
        RAND_bytes(ID, ID_LENGTH);
        memberId = bytesToHex(ID, ID_LENGTH);
        if (IDLG[j] == memberId)
        {
            continue;
        }
        else
        {
            // 2. Perform Join operation to get shared key
            Ax = ra.Join(nullptr, memberId, currentTime);

            // 3. Generate SG and compare
            alpha_ID = bytesToInt(Ax[1]);
            SG = SGGen(Ax[0], 16, alpha_ID, params);
            // just need compare SG_LENGTH length
            if (memcmp(SG_hex, SG.c_str(), 2 * SG_LENGTH) == 0)
            {
                // 4. Store shared key
                SKeys.storeKey(alpha_ID, Ax[0], 16);
            }
            // Clean up memory - adjust according to actual allocation method
            if (Ax[0] != nullptr)
            {
                delete[] Ax[0];
                Ax[0] = nullptr;
            }
            if (Ax[1] != nullptr)
            {
                delete[] Ax[1];
                Ax[1] = nullptr;
            }
        }
    }

    // First get all alpha IDs
    std::vector<size_t> alphaIDVec = SKeys.getAllAlphaIDs();
    Z = alphaIDVec.size();
    std::cout << "Z=" << Z << std::endl;
    std::cout << std::endl;
    for (const auto &alphaID : alphaIDVec)
    {
        std::cout << "Found member assign number=" << alphaID << std::endl;

        // 5. Get shared key
        shared_key = SKeys.getKey(alphaID);

        // 6. Calculate kij
        prf(kij, 16, shared_key.data(), 16, current_epoch_j);

        // Immediately clean up stored key
        // SKeys.removeKey(alphaID);

        // 7. Calculate mac key
        prf1(k_mac, 16, kij, 16, SG_hex, 2 * SG_LENGTH);

        // 8. Calculate MAC
        prf1(mac, 16, k_mac, 16, received_msg, received_msg_len);

        std::cout << "mac: ";
        printBytes(mac, 16);
        std::cout << std::endl;

        // 9. Add to MAC collection
        mac_vector.assign(mac, mac + 16);
        mac_collection.push_back(mac_vector);

        // 10. Shuffle MAC order
        if (mac_collection.size() > 1)
        {
            static std::random_device rd;
            static std::mt19937 g(rd());
            std::shuffle(mac_collection.begin(), mac_collection.end(), g);
        }
    }

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
    const std::string sgId = "DGTOTP";
    const long sharedStartTime = getSharedProtocolStartTimeMillis();

    // Initialize RA
    RA ra; // Create RA instance
    Parameter params;
    params.init(sgId, sharedStartTime);
    ra.RASetup(k, params.getG(), params.getU(), params.getStartTime(), params.getEndTime(), params.getDeltaE(), params.getDeltaS());
    std::cout << "RA group public key: " << ra.getGpk() << std::endl;

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

                const long joinTime = getCurrentTimeMillis();
                std::vector<unsigned char *> Ax = ra.Join(nullptr, memberId, joinTime);
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

                    std::vector<std::vector<unsigned char>> macs = MacGen(ra, params, received_msg, received_msg_len);
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
                    ra.GMUpdate(verifyTime, params);
                    Verifier verifier;
                    int verifyResult = verifier.Verify(password, verifyTime, params);
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
    ra.cleanup();
    params.cleanup();

    return 0;
}
