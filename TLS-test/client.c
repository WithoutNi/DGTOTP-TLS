#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define VERIFIER_IP "127.0.0.1"
#define VERIFIER_PORT 4434
#define BUFFER_SIZE 1024

// 全局变量保存Finished消息
static unsigned char finished_msg[BUFFER_SIZE];
static size_t finished_msg_len = 0;

void msg_callback(int write_p, int version, int content_type, 
                 const void *buf, size_t len, SSL *ssl, void *arg) {
    if (content_type != SSL3_RT_HANDSHAKE) return;
    (void)version;
    (void)ssl;
    (void)arg;
    const unsigned char *p = buf;
    if (len > 0 && p[0] == SSL3_MT_FINISHED && write_p) {
        printf("\n--- sent Finished Message (%zu bytes) ---\n", len);
        
        // 保存Finished消息
        memcpy(finished_msg, buf, len);
        finished_msg_len = len;
        
        // 打印消息
        for (size_t i = 0; i < len; i++) {
            printf("%02X ", finished_msg[i]);
            if ((i + 1) % 16 == 0) printf("\n");
        }
        printf("\n");
    }
}

SSL_CTX* create_context() {
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("SSL_CTX_new failed");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

int main() {
    SSL_CTX *ctx;
    int sockfd;
    struct sockaddr_in verifier_addr;

    // 初始化 OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // 创建 SSL 上下文
    ctx = create_context();
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);

    // 创建 TCP 连接 (连接到 Verifier)
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&verifier_addr, 0, sizeof(verifier_addr));
    verifier_addr.sin_family = AF_INET;
    verifier_addr.sin_port = htons(VERIFIER_PORT);
    inet_pton(AF_INET, VERIFIER_IP, &verifier_addr.sin_addr);

    if (connect(sockfd, (struct sockaddr*)&verifier_addr, sizeof(verifier_addr))) {
        perror("Failed to connect to verifier");
        exit(EXIT_FAILURE);
    }

    // 创建 SSL 连接
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    // 设置消息回调
    SSL_set_msg_callback(ssl, msg_callback);
    SSL_set_msg_callback_arg(ssl, NULL);

    // 执行 TLS 握手
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        printf("Connected to verifier with %s\n", SSL_get_cipher(ssl));
        
        // 发送自定义数据
        const char *msg = "Hello from Client!";
        SSL_write(ssl, msg, strlen(msg));

        // 接收响应
        char buf[BUFFER_SIZE];
        int bytes = SSL_read(ssl, buf, sizeof(buf));
        if (bytes > 0) {
            buf[bytes] = '\0';
            printf("Verifier response: %s\n", buf);
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sockfd);
    return 0;
}