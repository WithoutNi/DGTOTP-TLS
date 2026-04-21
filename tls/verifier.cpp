#include <iostream>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <string>
#include <vector>
#include <ctime>
#include <chrono>

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
#include "util.h"

#define CLIENT_PORT 4434
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 4433
#define BUFFER_SIZE 4096
#define SERVER_CONNECT_RETRY_COUNT 50
#define SERVER_CONNECT_RETRY_DELAY_US 200000

// Global variables to store Finished message
static unsigned char fin_msg[BUFFER_SIZE];
static size_t fin_msg_len = 0;
// Global variables to store Commitment message
static unsigned char Com[BUFFER_SIZE];
static size_t Com_len = 0;

int ComVerify(unsigned char *msg, size_t msg_len, unsigned char *fin_msg, size_t fin_msg_len, unsigned char *com, size_t com_len)
{
    // Convert received message to string
    std::string received_data((char *)msg, msg_len);

    // Remove PW prefix (first 3 bytes)
    std::string pw_data = received_data.substr(3);

    std::vector<std::string> password;

    // Extract fields using known lengths (ensure correct length)
    if (pw_data.length() >= 64 + 32 + 20)
    {
        password.push_back(pw_data.substr(0, 64));       // TOTP Password
        password.push_back(pw_data.substr(64, 32));      // Chameleon Hash
        password.push_back(pw_data.substr(64 + 32, 20)); // Identity Ciphertext
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
    std::cout << "TOTP Password: " << password[0] << std::endl;
    std::cout << "Chameleon Hash: " << string_to_hex(password[1]) << std::endl;
    std::cout << "Identity Ciphertext: " << string_to_hex(password[2]) << std::endl;
    std::cout << "UCM: " << commitment.UCM << std::endl;
    std::cout << "SCM: " << commitment.SCM << std::endl;
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

// Callback function to capture Finished message
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

// Create SSL context (server mode)
SSL_CTX *create_server_context()
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

int connect_to_server_with_retry(const struct sockaddr_in &server_addr)
{
    int last_errno = 0;

    for (int attempt = 1; attempt <= SERVER_CONNECT_RETRY_COUNT; ++attempt)
    {
        int server_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (server_sock < 0)
        {
            perror("socket");
            return -1;
        }

        if (connect(server_sock, (const struct sockaddr *)&server_addr, sizeof(server_addr)) == 0)
        {
            if (attempt > 1)
            {
                printf("Connected to server after %d attempts\n", attempt);
            }
            return server_sock;
        }

        last_errno = errno;
        close(server_sock);

        if (attempt == 1 || attempt % 10 == 0)
        {
            printf("Server not ready on %s:%d, retrying... (%d/%d)\n",
                   SERVER_IP, SERVER_PORT, attempt, SERVER_CONNECT_RETRY_COUNT);
        }

        usleep(SERVER_CONNECT_RETRY_DELAY_US);
    }

    errno = last_errno;
    perror("Failed to connect to server");
    return -1;
}

// Configure server context
void configure_server_context(SSL_CTX *ctx)
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

int main()
{
    // Part 1: Act as server to accept Client connection
    SSL_CTX *server_ctx = create_server_context();
    configure_server_context(server_ctx);

    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    // Create server socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(CLIENT_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    listen(server_fd, 5);

    printf("Verifier listening for client on port %d\n", CLIENT_PORT);

    // Accept client connection
    client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
    SSL *client_ssl = SSL_new(server_ctx);
    SSL_set_fd(client_ssl, client_fd);

    // Set message callback
    SSL_set_msg_callback(client_ssl, msg_callback);
    SSL_set_msg_callback_arg(client_ssl, NULL);

    unsigned char client_msg[BUFFER_SIZE];
    int client_msg_length = 0;

    // Perform TLS handshake
    if (SSL_accept(client_ssl))
    {
        printf("client-verifier TLS 1.3 handshake successful\n");

        // Receive client message
        client_msg_length = SSL_read(client_ssl, client_msg, sizeof(client_msg) - 1);
        if (client_msg_length > 0)
        {
            client_msg[client_msg_length] = '\0';
            printf("Received from client: %s\n", client_msg);
            const unsigned char *content = (const unsigned char *)(client_msg + strlen("MSG:"));
            Com_len = 2 * 2 * SHA256_DIGEST_LENGTH;
            printf("received commitment:");
            memcpy(Com, content, Com_len);
            for (size_t i = 0; i < Com_len; i++)
            {
                printf("%c", Com[i]);
            }
            printf("\n");
        }
    }
    else
    {
        ERR_print_errors_fp(stderr);
        // Clean up resources and exit
        SSL_free(client_ssl);
        close(client_fd);
        close(server_fd);
        SSL_CTX_free(server_ctx);
        return 1;
    }

    // Part 2: Act as client to connect to Server
    SSL_CTX *client_ctx = create_client_context();
    SSL_CTX_set_min_proto_version(client_ctx, TLS1_3_VERSION);

    struct sockaddr_in server_addr2;
    memset(&server_addr2, 0, sizeof(server_addr2));
    server_addr2.sin_family = AF_INET;
    server_addr2.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr2.sin_addr);

    int server_sock = connect_to_server_with_retry(server_addr2);
    if (server_sock < 0)
    {
        // Clean up resources
        SSL_free(client_ssl);
        close(client_fd);
        close(server_fd);
        SSL_CTX_free(server_ctx);
        SSL_CTX_free(client_ctx);
        close(server_sock);
        return 1;
    }

    SSL *server_ssl = SSL_new(client_ctx);
    SSL_set_fd(server_ssl, server_sock);

    unsigned char server_response[BUFFER_SIZE];
    int server_response_length = 0;

    // Perform TLS handshake and communication
    if (SSL_connect(server_ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
    }
    else
    {
        printf("verifier-server TLS 1.3 handshake successful\n");

        if (client_msg_length > 0)
        {
            // Forward client message to server
            int bytes_sent = SSL_write(server_ssl, client_msg, client_msg_length);
            if (bytes_sent > 0)
            {
                printf("Forwarded %d bytes commitment to server\n", bytes_sent);

                // Receive server response
                server_response_length = SSL_read(server_ssl, server_response, sizeof(server_response) - 1);
                if (server_response_length > 0)
                {
                    server_response[server_response_length] = '\0';
                    printf("Received mac from server: %d bytes\n", server_response_length);
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
                    else
                    {
                        printf("Failed to send response to client\n");
                    }
                }
                else
                {
                    printf("No response from server\n");
                }
            }
            else
            {
                printf("Failed to send message to server\n");
            }
        }
        else
        {
            printf("No message from client to forward\n");
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
                int result = ComVerify(new_client_msg, new_msg_length, fin_msg, fin_msg_len, Com, Com_len);

                if (result == 1)
                {
                    // Forward to server
                    int sent = SSL_write(server_ssl, new_client_msg, new_msg_length);
                    if (sent > 0)
                    {
                        printf("Forwarded to server: %d bytes\n", sent);

                        // Wait for server response
                        unsigned char new_server_response[BUFFER_SIZE];
                        int response_len = SSL_read(server_ssl, new_server_response, sizeof(new_server_response) - 1);
                        if (response_len > 0)
                        {
                            new_server_response[response_len] = '\0';
                            printf("Received from server: %s\n", new_server_response);
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
    SSL_shutdown(server_ssl);
    SSL_free(server_ssl);
    SSL_shutdown(client_ssl);
    SSL_free(client_ssl);
    SSL_CTX_free(server_ctx);
    SSL_CTX_free(client_ctx);
    close(server_sock);
    close(client_fd);
    close(server_fd);

    return 0;
}
