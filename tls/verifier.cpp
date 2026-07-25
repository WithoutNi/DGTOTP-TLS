#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <string>
#include <vector>
#include <ctime>
#include <stdexcept>

#include <unistd.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "Parameter.h"
#include "ChameleonHash.h"
#include "MerkleTrees.h"
#include "TOTP.h"
#include "Member.h"
#include "RA.h"
#include "Verifier.h"
#include "DGTOTP_PRF.h"
#ifndef UTIL_H
#include "util.h"
#endif
#include "KeyGen.h"

#define CLIENT_PORT 4434
#define SERVER_AS_IP "127.0.0.1"
#define SERVER_RA_IP "127.0.0.1"
#define SERVER_AS_PORT 4433
#define SERVER_RA_PORT 4436
#define BUFFER_SIZE 4096
#define SERVER_CONNECT_RETRY_COUNT 50
#define SERVER_CONNECT_RETRY_DELAY_US 200000

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

int CMVerify(unsigned char *msg, size_t msg_len, unsigned char *fin_msg, size_t fin_msg_len, unsigned char *com, size_t com_len)
{
    // Convert received message to string
    std::string received_data((char *)msg, msg_len);

    // Check PW prefix
    if (received_data.substr(0, 3) != "PW:")
    {
        return 0;
    }

    // Remove PW prefix (first 3 bytes)
    std::string pw_data = received_data.substr(3);

    std::vector<std::string> password;

    // Extract fields using known lengths (ensure correct length)
    if (pw_data.length() >= 32 + 32 + 20)
    {
        password.push_back(pw_data.substr(0, 32));       // TOTP Password
        password.push_back(pw_data.substr(32, 32));      // Chameleon Hash
        password.push_back(pw_data.substr(32 + 32, 20)); // Identity Ciphertext
    }
    else
    {
        // Insufficient data length, verification failed
        return 0;
    }

    // Debug information (optional, can be commented out in release version)
    printf("fin_msg:%ld bytes\n", fin_msg_len);
    for (size_t i = 0; i < fin_msg_len; i++)
    {
        printf("%02X ", fin_msg[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    printf("\n");

    // Generate commitment
    pw_CM commitment = CMGen(password, fin_msg, fin_msg_len);
    std::string serializedCommitment = commitment.UCM + commitment.SCM;

    // Debug information (optional, can be commented out in release version)
    std::cout << "TOTP Password: " << string_to_hex(password[0]) << std::endl;
    std::cout << "Chameleon Hash: " << string_to_hex(password[1]) << std::endl;
    std::cout << "Identity Ciphertext: " << string_to_hex(password[2]) << std::endl;
    std::cout << "UCM: " << string_to_hex(commitment.UCM) << std::endl;
    std::cout << "SCM: " << string_to_hex(commitment.SCM) << std::endl;
    std::cout << std::endl;

    // Compare commitment values, memcmp returns 0 if equal
    if (memcmp(com, serializedCommitment.c_str(), com_len) == 0)
    {
        std::cout << "Commitment Verify Success" << std::endl;
        return 1; // Verification successful
    }
    else
    {
        return 0; // Verification failed
    }
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

// Create SSL context (server mode)
SSL_CTX *create_server_context()
{
    int iRet = 0;
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    iRet = (ctx != NULL) ? 1 : 0;
    CHECK_SSL_CTX(iRet, "SSL_CTX_new");

    iRet = SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    CHECK_SSL_CTX(iRet, "SSL_CTX_set_min_proto_version");

    iRet = SSL_CTX_set_num_tickets(ctx, 0);
    CHECK_SSL_CTX(iRet, "SSL_CTX_set_num_tickets");

    iRet = SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256");
    CHECK_SSL_CTX(iRet, "SSL_CTX_set_ciphersuites");

    // Using verifier.crt and verifier.key for Client-Verifier connection
    iRet = SSL_CTX_use_certificate_file(ctx, "verifier.crt", SSL_FILETYPE_PEM);
    CHECK_SSL_CTX(iRet, "SSL_CTX_use_certificate_file");

    iRet = SSL_CTX_use_PrivateKey_file(ctx, "verifier.key", SSL_FILETYPE_PEM);
    CHECK_SSL_CTX(iRet, "SSL_CTX_use_PrivateKey_file");

    iRet = SSL_CTX_check_private_key(ctx);
    CHECK_SSL_CTX(iRet, "SSL_CTX_check_private_key");

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

    iRet = SSL_CTX_use_certificate_file(ctx, "verifier.crt", SSL_FILETYPE_PEM);
    CHECK_SSL_CTX(iRet, "SSL_CTX_use_certificate_file");

    iRet = SSL_CTX_use_PrivateKey_file(ctx, "verifier.key", SSL_FILETYPE_PEM);
    CHECK_SSL_CTX(iRet, "SSL_CTX_use_PrivateKey_file");

    iRet = SSL_CTX_check_private_key(ctx);
    CHECK_SSL_CTX(iRet, "SSL_CTX_check_private_key");

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    iRet = SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL);
    CHECK_SSL_CTX(iRet, "SSL_CTX_load_verify_locations");

    return ctx;
}

int connect_to_server_with_retry(const char *server_ip, int server_port)
{
    int last_errno = 0;
    struct sockaddr_in server_addr;

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);

    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0)
    {
        fprintf(stderr, "Invalid IP address: %s\n", server_ip);
        return -1;
    }

    for (int attempt = 1; attempt <= SERVER_CONNECT_RETRY_COUNT; ++attempt)
    {
        int server_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (server_sock < 0)
        {
            perror("socket creation failed");
            return -1;
        }

        if (connect(server_sock, (const struct sockaddr *)&server_addr, sizeof(server_addr)) == 0)
        {
            if (attempt > 1)
            {
                printf("Connected to server %s:%d after %d attempts\n",
                       server_ip, server_port, attempt);
            }
            return server_sock;
        }

        last_errno = errno;
        close(server_sock);

        if (attempt == 1 || attempt % 10 == 0 || attempt == SERVER_CONNECT_RETRY_COUNT)
        {
            printf("Server not ready on %s:%d, retrying... (%d/%d)\n",
                   server_ip, server_port, attempt, SERVER_CONNECT_RETRY_COUNT);
        }

        usleep(SERVER_CONNECT_RETRY_DELAY_US);
    }

    errno = last_errno;
    fprintf(stderr, "Failed to connect to server %s:%d after %d attempts\n",
            server_ip, server_port, SERVER_CONNECT_RETRY_COUNT);
    return -1;
}

int main()
{
    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Generate verifier certificate and key if they don't exist
    std::string key_file = "verifier.key";
    std::string cert_file = "verifier.crt";
    if (!fileExists(key_file) || !fileExists(cert_file))
    {
        std::cout << "verifier certificate or key not found, generating..." << std::endl;
        if (!GenerateKeyAndCertificate(key_file, cert_file))
        {
            std::cerr << "Failed to generate verifier certificate and key" << std::endl;
            return 1;
        }
        std::cout << "verifier certificate and key generated successfully" << std::endl;
    }
    else
    {
        std::cout << "verifier certificate and key already exist, skipping generation" << std::endl;
    }

    // Part 1: Act as server to accept Client connection (One-Way TLS)
    SSL_CTX *server_ctx = create_server_context();

    int client_sockfd, client_fd;
    struct sockaddr_in verifier_addr;

    // Create server socket
    client_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&verifier_addr, 0, sizeof(verifier_addr));
    verifier_addr.sin_family = AF_INET;
    verifier_addr.sin_port = htons(CLIENT_PORT);
    verifier_addr.sin_addr.s_addr = INADDR_ANY;

    bind(client_sockfd, (struct sockaddr *)&verifier_addr, sizeof(verifier_addr));
    listen(client_sockfd, 5);

    printf("Verifier listening for client on port %d\n", CLIENT_PORT);

    // Accept client connection
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    client_fd = accept(client_sockfd, (struct sockaddr *)&client_addr, &client_len);
    SSL *client_ssl = SSL_new(server_ctx);
    SSL_set_fd(client_ssl, client_fd);

    // Set message callback
    SSL_set_msg_callback(client_ssl, msg_callback);
    SSL_set_msg_callback_arg(client_ssl, NULL);

    unsigned char client_msg[BUFFER_SIZE];
    int client_msg_length = 0;
    unsigned char PURec[BUFFER_SIZE];
    int Com_len = 0;
    int SGId = 0;

    // Perform TLS handshake
    if (SSL_accept(client_ssl))
    {
        printf("client-verifier TLS 1.3 handshake successful\n");

        // Receive client message PURec
        client_msg_length = SSL_read(client_ssl, client_msg, sizeof(client_msg) - 1);
        if (client_msg_length > 0)
        {
            client_msg[client_msg_length] = '\0';
            Com_len = 2 * SHA256_DIGEST_LENGTH;
            const size_t msg_prefix_len = strlen("PURec:");
            if (static_cast<size_t>(client_msg_length) < msg_prefix_len + Com_len ||
                memcmp(client_msg, "PURec:", msg_prefix_len) != 0)
            {
                throw std::runtime_error("Received client commitment message is invalid");
            }

            printf("Received from client: %d bytes\n", client_msg_length);
            const unsigned char *content = client_msg + msg_prefix_len;
            printf("received commitment:");
            memcpy(PURec, content, Com_len);
            for (size_t i = 0; i < Com_len; i++)
            {
                printf("%02X", PURec[i]);
            }
            printf("\n");
            SGId = content[Com_len];
            printf("received SGId:%d\n", SGId);
        }
    }
    else
    {
        ERR_print_errors_fp(stderr);
        // Clean up resources and exit
        SSL_free(client_ssl);
        close(client_fd);
        close(client_sockfd);
        SSL_CTX_free(server_ctx);
        return 1;
    }

    // Part 2: Act as client to connect to Server_AS (Mutual Authentication TLS)
    SSL_CTX *client_ctx = create_client_context();

    int as_sock = connect_to_server_with_retry(SERVER_AS_IP, SERVER_AS_PORT);
    if (as_sock < 0)
    {
        // Clean up resources
        SSL_free(client_ssl);
        close(client_fd);
        close(client_sockfd);
        SSL_CTX_free(server_ctx);
        SSL_CTX_free(client_ctx);
        return 1;
    }

    SSL *as_ssl = SSL_new(client_ctx);
    SSL_set_fd(as_ssl, as_sock);

    unsigned char server_response[BUFFER_SIZE];
    int server_response_length = 0;
    bool as_connected = false;

    // Perform TLS handshake and communication
    if (SSL_connect(as_ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
        // Clean up resources and exit
        SSL_free(as_ssl);
        close(as_sock);
        SSL_free(client_ssl);
        close(client_fd);
        close(client_sockfd);
        SSL_CTX_free(server_ctx);
        SSL_CTX_free(client_ctx);
        return 1;
    }
    else
    {
        as_connected = true;
        printf("verifier-server TLS 1.3 handshake successful\n");

        if (client_msg_length > 0)
        {
            // Forward client message to server
            int bytes_sent = SSL_write(as_ssl, client_msg, client_msg_length);
            if (bytes_sent > 0)
            {
                printf("Forwarded %d bytes commitment to server\n", bytes_sent);

                // Receive server response
                server_response_length = SSL_read(as_ssl, server_response, sizeof(server_response) - 1);
                if (server_response_length > 0)
                {
                    server_response[server_response_length] = '\0';
                    printf("Received tags from server: %d bytes\n", server_response_length);
                    for (int i = 0; i < server_response_length; i++)
                    {
                        printf("%02X ", server_response[i]);
                        if ((i + 1) % 16 == 0)
                            printf("\n");
                    }
                    printf("\n");

                    // Return server response to client
                    int bytes_sent_to_client = SSL_write(client_ssl, server_response, server_response_length);
                    if (bytes_sent_to_client > 0)
                    {
                        printf("Forwarded %d bytes from server to client\n", bytes_sent_to_client);
                    }
                }
            }
        }
    }

    // Part 3: Maintain client connection and handle subsequent communication
    printf("Wait message from the client\n");
    bool keep_running = true;

    while (keep_running)
    {
        // Check if client has password
        unsigned char new_client_msg[BUFFER_SIZE];
        fd_set read_fds;
        struct timeval timeout;

        FD_ZERO(&read_fds);
        FD_SET(client_fd, &read_fds);
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        int select_result = select(client_fd + 1, &read_fds, NULL, NULL, &timeout);

        if (select_result > 0 && FD_ISSET(client_fd, &read_fds))
        {
            // Read client message
            int new_msg_length = SSL_read(client_ssl, new_client_msg, sizeof(new_client_msg) - 1);
            if (new_msg_length > 0)
            {
                new_client_msg[new_msg_length] = '\0';
                printf("Received DGTOTP password from client: %d bytes\n", new_msg_length);
                if (new_msg_length < 3 || memcmp(new_client_msg, "PW:", 3) != 0)
                {
                    continue;
                }
                int result = CMVerify(new_client_msg, new_msg_length, fin_msg, fin_msg_len, PURec, Com_len);

                if (result == 1)
                {
                    // Part 4: Act as client to connect to Server_RA (Mutual Authentication TLS)
                    int ra_sock = connect_to_server_with_retry(SERVER_RA_IP, SERVER_RA_PORT);
                    if (ra_sock < 0)
                    {
                        fprintf(stderr, "Failed to connect to RA\n");
                        continue;
                    }
                    SSL *ra_ssl = SSL_new(client_ctx);
                    SSL_set_fd(ra_ssl, ra_sock);

                    // Perform TLS handshake and communication
                    if (SSL_connect(ra_ssl) > 0)
                    {
                        // Build message: original PW message + SGId at the end
                        std::string pw_with_sgid;
                        pw_with_sgid.reserve(new_msg_length + SG_LENGTH_BYTES);
                        pw_with_sgid.append(reinterpret_cast<char *>(new_client_msg), new_msg_length);
                        pw_with_sgid.push_back(static_cast<unsigned char>(SGId));

                        int sent = SSL_write(ra_ssl, pw_with_sgid.c_str(), pw_with_sgid.size());

                        if (sent > 0)
                        {
                            printf("Forwarded pw to RA: %d bytes\n", sent);

                            // Wait for server response
                            unsigned char new_server_response[BUFFER_SIZE];
                            int response_len = SSL_read(ra_ssl, new_server_response, sizeof(new_server_response) - 1);
                            if (response_len > 0)
                            {
                                new_server_response[response_len] = '\0';
                                printf("Received from RA: %s\n", new_server_response);
                                printf("\n");

                                // Return to client
                                int client_sent = SSL_write(client_ssl, new_server_response, response_len);
                                if (client_sent > 0)
                                {
                                    printf("Forwarded to client: %d bytes\n", client_sent);
                                    printf("\n");
                                }
                            }
                        }
                    }
                    else
                    {
                        ERR_print_errors_fp(stderr);
                    }

                    // Clean up RA connection
                    SSL_shutdown(ra_ssl);
                    SSL_free(ra_ssl);
                    if (ra_sock > 0)
                        close(ra_sock);
                }
            }
            else if (new_msg_length == 0)
            {
                // Client disconnected
                printf("Client disconnected\n");
                keep_running = false;
            }
        }

        // Check if server has active messages (if needed)
        // Add server active message handling here if needed

        // Simple exit condition (can have more complex logic in real applications)
        if (select_result < 0)
        {
            perror("select error");
            keep_running = false;
        }
    }

    // Clean up resources
    printf("Cleaning up resources...\n");

    // Clean up AS connection
    if (as_connected)
    {
        SSL_shutdown(as_ssl);
        SSL_free(as_ssl);
    }
    if (as_sock > 0)
        close(as_sock);

    // Clean up Client connection
    SSL_shutdown(client_ssl);
    SSL_free(client_ssl);
    close(client_fd);
    close(client_sockfd);

    // Clean up SSL contexts
    SSL_CTX_free(server_ctx);
    SSL_CTX_free(client_ctx);

    return 0;
}