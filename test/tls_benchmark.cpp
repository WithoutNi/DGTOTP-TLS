#define _POSIX_C_SOURCE 199309L

#include <iostream>
#include <cstring>
#include <string>
#include <vector>
#include <ctime>
#include <chrono>
#include <thread>
#include <atomic>
#include <numeric>

#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bio.h>

// Adjust this path if necessary depending on your workspace layout
#include "cycles.h"

#define PORT_ONE_WAY 4440
#define PORT_TWO_WAY 4441
#define NTESTS 1000

// Certificate path macros
#define CA_CERT "ca.crt"
#define SERVER_CERT "AS.crt"
#define SERVER_KEY "AS.key"
#define VERIFIER_CERT "verifier.crt"
#define VERIFIER_KEY "verifier.key"

// Structures to pass server statistics back to main thread
struct HandshakeSample
{
    unsigned long long cycles;
    double time_us;
    size_t bytes_sent;
    size_t bytes_received;
};

static HandshakeSample server_samples[NTESTS];
static std::atomic<int> server_sample_idx(0);

// ==========================================
// Auxiliary statistical functions
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

// Formats results and adds traffic statistics
static void print_side_results(const std::string &label,
                               const std::vector<unsigned long long> &individual_cycles,
                               const std::vector<double> &individual_times,
                               const std::vector<size_t> &sent_bytes,
                               const std::vector<size_t> &received_bytes)
{
    double total_time_us = 0;
    double total_sent = 0;
    double total_recv = 0;

    for (size_t i = 0; i < NTESTS; ++i)
    {
        total_time_us += individual_times[i];
        total_sent += sent_bytes[i];
        total_recv += received_bytes[i];
    }

    // Convert individual cycle metrics into a cumulative list for delta()
    std::vector<unsigned long long> cumulative_cycles(NTESTS + 1, 0);
    for (size_t idx = 0; idx < NTESTS; idx++)
    {
        cumulative_cycles[idx + 1] = cumulative_cycles[idx] + individual_cycles[idx];
    }

    printf("%-22s", label.c_str());
    display_result(total_time_us, cumulative_cycles.data(), NTESTS, 1);

    // Print Network Traffic Stats
    printf("%-22s avg. Sent: %10.1f bytes, avg. Received: %10.1f bytes, total: %10.1f bytes\n",
           " ", total_sent / NTESTS, total_recv / NTESTS, (total_sent + total_recv) / NTESTS);
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
    SSL_CTX_set_num_tickets(ctx, 0); // Disable session tickets for clean handshake measurement
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

    if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY, SSL_FILETYPE_PEM) <= 0)
    {
        std::cerr << "Error loading server cert or key for Two-Way." << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

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

    if (SSL_CTX_use_certificate_file(ctx, VERIFIER_CERT, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, VERIFIER_KEY, SSL_FILETYPE_PEM) <= 0)
    {
        std::cerr << "Error loading verifier cert or key for Two-Way." << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

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
        timeout.tv_usec = 50000;

        int sel = select(server_fd + 1, &read_fds, NULL, NULL, &timeout);
        if (sel <= 0)
            continue;

        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0)
            continue;

        SSL *ssl = SSL_new(server_ctx);
        SSL_set_fd(ssl, client_fd);

        // Get internal BIO for traffic monitoring
        BIO *rbio = SSL_get_rbio(ssl);
        BIO *wbio = SSL_get_wbio(ssl);
        unsigned long long b_read_before = BIO_number_read(rbio);
        unsigned long long b_write_before = BIO_number_written(wbio);

        struct timespec s_start, s_stop;
        clock_gettime(CLOCK_MONOTONIC, &s_start);
        unsigned long long c_start = cpucycles();

        int ret = SSL_accept(ssl);

        unsigned long long c_stop = cpucycles();
        clock_gettime(CLOCK_MONOTONIC, &s_stop);

        if (ret > 0)
        {
            int idx = server_sample_idx.fetch_add(1);
            if (idx < NTESTS)
            {
                server_samples[idx].cycles = c_stop - c_start;
                server_samples[idx].time_us = ((double)(s_stop.tv_sec - s_start.tv_sec) * 1e6 +
                                               (double)(s_stop.tv_nsec - s_start.tv_nsec) / 1e3);

                // Track traffic deltas
                server_samples[idx].bytes_received = BIO_number_read(rbio) - b_read_before;
                server_samples[idx].bytes_sent = BIO_number_written(wbio) - b_write_before;
            }
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
    }
}

// ==========================================
// Client Handshake Profile Routine
// ==========================================

void run_client_handshake_profile(SSL_CTX *client_ctx, int port,
                                  std::vector<unsigned long long> &client_cycles,
                                  std::vector<double> &client_times,
                                  std::vector<size_t> &client_sent,
                                  std::vector<size_t> &client_received)
{
    int client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd < 0)
        return;

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

            BIO *rbio = SSL_get_rbio(ssl);
            BIO *wbio = SSL_get_wbio(ssl);
            unsigned long long b_read_before = BIO_number_read(rbio);
            unsigned long long b_write_before = BIO_number_written(wbio);

            struct timespec c_start, c_stop;
            clock_gettime(CLOCK_MONOTONIC, &c_start);
            unsigned long long cy_start = cpucycles();

            SSL_connect(ssl);

            unsigned long long cy_stop = cpucycles();
            clock_gettime(CLOCK_MONOTONIC, &c_stop);

            client_cycles.push_back(cy_stop - cy_start);
            client_times.push_back(((double)(c_stop.tv_sec - c_start.tv_sec) * 1e6 +
                                    (double)(c_stop.tv_nsec - c_start.tv_nsec) / 1e3));

            client_received.push_back(BIO_number_read(rbio) - b_read_before);
            client_sent.push_back(BIO_number_written(wbio) - b_write_before);

            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
    }
    close(client_fd);
}

// ==========================================
// Socket Helper
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
// Test Runner Orchestration
// ==========================================

void run_full_benchmark_suite(const std::string &title, SSL_CTX *server_ctx, SSL_CTX *client_ctx, int port)
{
    server_sample_idx = 0;
    std::memset(server_samples, 0, sizeof(server_samples));

    int server_fd = setup_server_socket(port);

    std::atomic<bool> server_ready(false);
    std::atomic<bool> server_running(true);

    std::thread server_thread(server_thread_func, server_ctx, server_fd,
                              std::ref(server_ready), std::ref(server_running));

    while (!server_ready)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::vector<unsigned long long> client_cycles;
    std::vector<double> client_times;
    std::vector<size_t> client_sent, client_recv;

    client_cycles.reserve(NTESTS);
    client_times.reserve(NTESTS);
    client_sent.reserve(NTESTS);
    client_recv.reserve(NTESTS);

    for (int idx = 0; idx < NTESTS; idx++)
    {
        run_client_handshake_profile(client_ctx, port, client_cycles, client_times, client_sent, client_recv);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    server_running = false;
    if (server_thread.joinable())
        server_thread.join();
    close(server_fd);

    std::vector<unsigned long long> s_cycles;
    std::vector<double> s_times;
    std::vector<size_t> s_sent, s_recv;

    for (int idx = 0; idx < NTESTS; idx++)
    {
        s_cycles.push_back(server_samples[idx].cycles);
        s_times.push_back(server_samples[idx].time_us);
        s_sent.push_back(server_samples[idx].bytes_sent);
        s_recv.push_back(server_samples[idx].bytes_received);
    }

    std::cout << "============================================================" << std::endl;
    std::cout << " Suite: " << title << std::endl;
    std::cout << "============================================================" << std::endl;
    print_side_results(title + " (Client)", client_cycles, client_times, client_sent, client_recv);
    print_side_results(title + " (Server)", s_cycles, s_times, s_sent, s_recv);
    std::cout << "============================================================" << std::endl;
    std::cout << std::endl;
}

// ==========================================
// Main Benchmark Entry Point
// ==========================================

int main()
{
    init_cpucycles();

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    std::cout << "Starting TLS 1.3 Handshake Benchmark (" << NTESTS << " iterations per test)..." << std::endl
              << std::endl;

    // Test 1: One-Way Authentication
    {
        SSL_CTX *server_ctx_1w = create_server_context_one_way();
        SSL_CTX *client_ctx_1w = create_client_context_one_way();

        run_full_benchmark_suite("TLS_One_Way", server_ctx_1w, client_ctx_1w, PORT_ONE_WAY);

        SSL_CTX_free(server_ctx_1w);
        SSL_CTX_free(client_ctx_1w);
    }

    // Test 2: Two-Way (Mutual) Authentication
    {
        SSL_CTX *server_ctx_2w = create_server_context_two_way();
        SSL_CTX *client_ctx_2w = create_client_context_two_way();

        run_full_benchmark_suite("TLS_Two_Way", server_ctx_2w, client_ctx_2w, PORT_TWO_WAY);

        SSL_CTX_free(server_ctx_2w);
        SSL_CTX_free(client_ctx_2w);
    }

    return 0;
}