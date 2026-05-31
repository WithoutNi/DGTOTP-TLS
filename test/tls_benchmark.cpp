#define _POSIX_C_SOURCE 199309L

#include <iostream>
#include <cstring>
#include <string>
#include <vector>
#include <ctime>
#include <chrono>
#include <thread>
#include <atomic>

#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

// Adjust this path if necessary depending on your workspace layout
#include "cycles.h"

#define PORT_ONE_WAY 4440
#define PORT_TWO_WAY 4441
#define NTESTS 10

// Certificate path macros
#define CA_CERT "ca.crt"
#define SERVER_CERT "server.crt"
#define SERVER_KEY "server.key"
#define VERIFIER_CERT "verifier.crt"
#define VERIFIER_KEY "verifier.key"

// ==========================================
// Benchmark measurement macros from benchmark.cpp
// ==========================================

#define MEASURE_GENERIC(TEXT, MUL, FNCALL, CORR)                                                                         \
    printf("%-15s", TEXT);                                                                                               \
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);                                                                     \
    for (i = 0; i < NTESTS; i++)                                                                                         \
    {                                                                                                                    \
        t[i] = cpucycles() / CORR;                                                                                       \
        FNCALL;                                                                                                          \
    }                                                                                                                    \
    t[NTESTS] = cpucycles();                                                                                             \
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stop);                                                                      \
    result = ((double)(stop.tv_sec - start.tv_sec) * 1e6 + (double)(stop.tv_nsec - start.tv_nsec) / 1e3) / (double)CORR; \
    display_result(result, t, NTESTS, MUL);

#define MEASURT(TEXT, MUL, FNCALL)         \
    MEASURE_GENERIC(                       \
        TEXT, MUL,                         \
        do {                               \
            for (int j = 0; j < 1000; j++) \
            {                              \
                FNCALL;                    \
            }                              \
        } while (0);                       \
        ,                                  \
        1000);

#define MEASURE(TEXT, MUL, FNCALL) MEASURE_GENERIC(TEXT, MUL, FNCALL, 1)

// ==========================================
// Auxiliary statistical functions (reused from benchmark.cpp)
// ==========================================

static int cmp_llu(const void *a, const void *b)
{
    const unsigned long long lhs = *static_cast<const unsigned long long *>(a);
    const unsigned long long rhs = *static_cast<const unsigned long long *>(b);
    if (lhs < rhs)
        return -1;
    if (lhs > rhs)
        return 1;
    return 0;
}

static unsigned long long median(unsigned long long *l, size_t llen)
{
    qsort(l, llen, sizeof(unsigned long long), cmp_llu);
    if (llen % 2)
        return l[llen / 2];
    return (l[llen / 2 - 1] + l[llen / 2]) / 2;
}

static void delta(unsigned long long *l, size_t llen)
{
    for (size_t i = 0; i < llen - 1; i++)
    {
        l[i] = l[i + 1] - l[i];
    }
}

static std::string commaString(unsigned long long n)
{
    std::string text = std::to_string(n);
    for (int i = static_cast<int>(text.length()) - 3; i > 0; i -= 3)
    {
        text.insert(static_cast<size_t>(i), ",");
    }
    return text;
}

static void display_result(double result, unsigned long long *l, size_t llen, unsigned long long mul)
{
    unsigned long long med;

    result /= NTESTS;
    delta(l, NTESTS + 1);
    med = median(l, llen);

    const std::string medText = commaString(med);
    const std::string scaledText = commaString(mul * med);
    printf("avg. %12.2lf us (%8.2lf ms); median %16s cycles, %5llux: %16s cycles\n",
           result, result / 1e3, medText.c_str(), mul, scaledText.c_str());
}

// ==========================================
// SSL Context Initialization (One-Way)
// ==========================================

SSL_CTX *create_server_context_one_way()
{
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        perror("SSL_CTX_new failed (server one-way)");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_num_tickets(ctx, 0);
    if (!SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256"))
    {
        fprintf(stderr, "Failed to set ciphersuites\n");
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY, SSL_FILETYPE_PEM) <= 0)
    {
        std::cerr << "Error loading server cert or key for One-Way." << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

SSL_CTX *create_client_context_one_way()
{
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        perror("SSL_CTX_new failed (client one-way)");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    return ctx;
}

// ==========================================
// SSL Context Initialization (Two-Way Mutual Auth)
// ==========================================

SSL_CTX *create_server_context_two_way()
{
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        perror("SSL_CTX_new failed (server two-way)");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_num_tickets(ctx, 0);
    if (!SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256"))
    {
        fprintf(stderr, "Failed to set ciphersuites\n");
        exit(EXIT_FAILURE);
    }

    // Load server certificate and key
    if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY, SSL_FILETYPE_PEM) <= 0)
    {
        std::cerr << "Error loading server cert or key for Two-Way." << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Configure client certificate verification
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    if (SSL_CTX_load_verify_locations(ctx, CA_CERT, NULL) <= 0)
    {
        std::cerr << "Error loading CA cert on server for Two-Way verification." << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

SSL_CTX *create_client_context_two_way()
{
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        perror("SSL_CTX_new failed (client two-way)");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);

    // Load verifier certificate and key
    if (SSL_CTX_use_certificate_file(ctx, VERIFIER_CERT, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, VERIFIER_KEY, SSL_FILETYPE_PEM) <= 0)
    {
        std::cerr << "Error loading verifier cert or key for Two-Way." << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Verify server certificate
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    if (SSL_CTX_load_verify_locations(ctx, CA_CERT, NULL) <= 0)
    {
        std::cerr << "Error loading CA cert on client for Two-Way verification." << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

// ==========================================
// Server Background Thread Logic
// ==========================================

void server_thread_func(SSL_CTX *server_ctx, int server_fd, std::atomic<bool> &ready, std::atomic<bool> &running)
{
    ready = true;
    while (running)
    {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(server_fd, &read_fds);
        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 50000; // 50ms timeout for graceful thread exit

        int sel = select(server_fd + 1, &read_fds, NULL, NULL, &timeout);
        if (sel <= 0)
        {
            continue;
        }

        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0)
        {
            continue;
        }

        SSL *ssl = SSL_new(server_ctx);
        SSL_set_fd(ssl, client_fd);

        if (SSL_accept(ssl) <= 0)
        {
            // Handshake failed or connection closed
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
    }
}

// ==========================================
// Client Helper for Handshake Execution
// ==========================================

void run_client_handshake(SSL_CTX *client_ctx, int port)
{
    int client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd < 0)
    {
        return;
    }

    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &target_addr.sin_addr);

    if (connect(client_fd, (struct sockaddr *)&target_addr, sizeof(target_addr)) >= 0)
    {
        SSL *ssl = SSL_new(client_ctx);
        if (ssl)
        {
            SSL_set_fd(ssl, client_fd);
            SSL_connect(ssl);
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
    }
    close(client_fd);
}

// ==========================================
// Socket Helpers
// ==========================================

int setup_server_socket(int port)
{
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0)
    {
        perror("Failed to create server socket");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 10) < 0)
    {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    return server_fd;
}

// ==========================================
// Main Benchmark Entry Point
// ==========================================

int main()
{
    // Initialize CPU cycles measurement
    init_cpucycles();

    // Initialize OpenSSL components
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Declarations for measurement macros
    unsigned long long t[NTESTS + 1];
    struct timespec start, stop;
    double result;
    unsigned int i;

    std::cout << "Starting TLS 1.3 Handshake Benchmark (" << NTESTS << " iterations per test)..." << std::endl;

    // ------------------------------------------
    // Test 1: One-Way Authentication
    // ------------------------------------------
    {
        SSL_CTX *server_ctx_1w = create_server_context_one_way();
        SSL_CTX *client_ctx_1w = create_client_context_one_way();

        int server_fd_1w = setup_server_socket(PORT_ONE_WAY);

        std::atomic<bool> server_ready_1w(false);
        std::atomic<bool> server_running_1w(true);

        std::thread server_thread_1w(server_thread_func, server_ctx_1w, server_fd_1w,
                                     std::ref(server_ready_1w), std::ref(server_running_1w));

        while (!server_ready_1w)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        MEASURE("TLS_One_Way..", 1, run_client_handshake(client_ctx_1w, PORT_ONE_WAY));

        server_running_1w = false;
        if (server_thread_1w.joinable())
        {
            server_thread_1w.join();
        }

        close(server_fd_1w);
        SSL_CTX_free(server_ctx_1w);
        SSL_CTX_free(client_ctx_1w);
    }

    // ------------------------------------------
    // Test 2: Two-Way (Mutual) Authentication
    // ------------------------------------------
    {
        SSL_CTX *server_ctx_2w = create_server_context_two_way();
        SSL_CTX *client_ctx_2w = create_client_context_two_way();

        int server_fd_2w = setup_server_socket(PORT_TWO_WAY);

        std::atomic<bool> server_ready_2w(false);
        std::atomic<bool> server_running_2w(true);

        std::thread server_thread_2w(server_thread_func, server_ctx_2w, server_fd_2w,
                                     std::ref(server_ready_2w), std::ref(server_running_2w));

        while (!server_ready_2w)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        MEASURE("TLS_Two_Way..", 1, run_client_handshake(client_ctx_2w, PORT_TWO_WAY));

        server_running_2w = false;
        if (server_thread_2w.joinable())
        {
            server_thread_2w.join();
        }

        close(server_fd_2w);
        SSL_CTX_free(server_ctx_2w);
        SSL_CTX_free(client_ctx_2w);
    }

    return 0;
}