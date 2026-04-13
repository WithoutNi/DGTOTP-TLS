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

#define VERIFIER_IP "127.0.0.1"
#define VERIFIER_PORT 4434
#define SERVER_PORT 4435
#define BUFFER_SIZE 1024

// Global variables to store Finished message
static unsigned char fin_msg[BUFFER_SIZE];
static size_t fin_msg_len = 0;
std::vector<unsigned char *> Ax;

// Helper function: get current timestamp (milliseconds)
long getCurrentTimeMillis()
{
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
}

// Calculate DGTOTP password
std::vector<std::string> PwGen(std::string memberId, std::vector<unsigned char *> Ax)
{
    std::cout << "Calculate DGTOTP password..." << std::endl;

    // Get current time
    long currentTime = getCurrentTimeMillis();
    std::cout << "Current timestamp: " << currentTime << std::endl;

    // Create member
    Member member1;
    member1.PInit(memberId);

    // Generate DGTOTP password
    std::cout << "Generate DGTOTP password..." << std::endl;
    std::vector<std::string> password = member1.PwGen(Ax, currentTime);

    return password;
}

std::string SGGen(unsigned char ki[], size_t key_len, size_t alpha_ID)
{
    long time = getCurrentTimeMillis();
    int j = (int)((time - Parameter::START_TIME) / Parameter::Δe);
    printf("ki=");
    for (size_t i = 0; i < key_len; i++)
    {
        printf("%02X ", ki[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    unsigned char kij[32];
    // index=current epoch index
    prf(kij, key_len, ki, key_len, j);
    printf("kij=");
    for (size_t i = 0; i < key_len; i++)
    {
        printf("%02X ", kij[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    unsigned char SG_bytes[SG_LENGTH];
    // index= user index
    prf(SG_bytes, SG_LENGTH, kij, key_len, alpha_ID);

    printf("sub group identity=");
    for (size_t i = 0; i < SG_LENGTH; i++)
    {
        printf("%02X ", SG_bytes[i]);
    }
    printf("\n");

    // Convert unsigned char array to hexadecimal string
    return bytesToHex(SG_bytes, SG_LENGTH, true);
}

int MACVerify(unsigned char ki[], std::string SG, std::string Com, const unsigned char *macs, size_t mac_len)
{
    unsigned char kij[16];
    // assume current epoch j=0
    prf(kij, 16, ki, 16, 0);
    unsigned char mac_key[16];
    prf1(mac_key, 16, kij, 16, (unsigned char *)SG.c_str(), 2 * SG_LENGTH);
    // Calculate MAC using shared key as parameter
    unsigned char mac[16];
    prf1(mac, 16, mac_key, 16, (unsigned char *)(Com + SG).c_str(), (Com + SG).size());
    std::cout << "mac: ";
    printBytes(mac, 16);
    std::cout << std::endl;
    // compare method should compare every 16 bytes in macs
    for (int i = 0; i < mac_len; i += 16)
    {
        if (memcmp(macs + i, mac, 16) == 0)
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
    if (len > 0 && p[0] == SSL3_MT_FINISHED && write_p)
    {
        printf("\n--- sent Finished Message (%zu bytes) ---\n", len);

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

    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

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

    std::string memberId;

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

        // Prepare memberId to send
        unsigned char ID[ID_LENGTH];
        RAND_bytes(ID, ID_LENGTH);

        memberId = bytesToHex(ID, ID_LENGTH);
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
                unsigned char *ks_data = (unsigned char *)malloc(16);
                memcpy(ks_data, server_response, 16);
                Ax.push_back(ks_data);
                unsigned char *alpha_data = (unsigned char *)malloc(4);
                memcpy(alpha_data, server_response + 16, 4);
                Ax.push_back(alpha_data);
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
    std::vector<std::string> password;
    std::string commitment;
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
            password = PwGen(memberId, Ax);
            size_t alpha_ID = bytesToInt(Ax[1]);
            printf("alpha_ID: %ld\n", alpha_ID);
            SG = SGGen(Ax[0], 16, alpha_ID);
            printf("fin_msg:%ld bytes\n", fin_msg_len);
            for (size_t i = 0; i < fin_msg_len; i++)
            {
                printf("%02X ", fin_msg[i]);
                if ((i + 1) % 16 == 0)
                    printf("\n");
            }
            printf("\n");
            commitment = ComGen(password, fin_msg, fin_msg_len);

            std::cout << "=== Calculation Complete ===" << std::endl;
            std::cout << "TOTP Password: " << password[0] << std::endl;
            std::cout << "Chameleon Hash: " << string_to_hex(password[1]) << std::endl;
            std::cout << "Identity Ciphertext: " << string_to_hex(password[2]) << std::endl;
            std::cout << "Commitment: " << commitment << std::endl;
            std::cout << "==========================" << std::endl;
        }
        catch (const std::exception &e)
        {
            std::cerr << "Error calculating password: " << e.what() << std::endl;
            return 1;
        }
        // message=COMMITMENT+SG
        std::string message = "MSG:" + bytesToHex(Ax[0], 16) + commitment + SG;

        // Send commitment and related information
        int bytes_sent = SSL_write(verifier_ssl, message.c_str(), message.length());
        if (bytes_sent > 0)
        {
            std::cout << "Successfully sent commitment data: " << message << std::endl;
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
                for (size_t i = 0; i < bytes; i++)
                {
                    printf("%02X ", buf[i]);
                    if ((i + 1) % 16 == 0)
                        printf("\n");
                }
                printf("\n");
                // verify mac
                int result = MACVerify(Ax[0], SG, commitment, buf, bytes);
                if (result == 1)
                {
                    printf("Verfiy mac success,sent DGTOTP password\n");
                    std::string pw = "PW:" + password[0] + password[1] + password[2];
                    int pw_len = SSL_write(verifier_ssl, pw.c_str(), pw.length());
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

    // Clean up resources
    free(Ax[0]);
    free(Ax[1]);
    Parameter::cleanup();
    ChameleonHash::cleanup();

    return 0;
}