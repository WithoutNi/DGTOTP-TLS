#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define CLIENT_PORT 4434
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 4433
#define BUFFER_SIZE 4096

// 全局变量保存Finished消息
static unsigned char finished_msg[BUFFER_SIZE];
static size_t finished_msg_len = 0;

// 回调函数捕获Finished消息
void msg_callback(int write_p, int version, int content_type, 
                 const void *buf, size_t len, SSL *ssl, void *arg) {
    if (content_type != SSL3_RT_HANDSHAKE) return;
    (void)version;
    (void)ssl;
    (void)arg;
    const unsigned char *p = buf;
    if (len > 0 && p[0] == SSL3_MT_FINISHED && !write_p) {
        printf("\n--- Received Finished Message (%zu bytes) ---\n", len);
        
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

// 创建SSL上下文 (服务器模式)
SSL_CTX* create_server_context() {
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("SSL_CTX_new failed");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

// 创建SSL上下文 (客户端模式)
SSL_CTX* create_client_context() {
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("SSL_CTX_new failed");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

// 配置服务器上下文
void configure_server_context(SSL_CTX *ctx) {
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    if (!SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256")) {
        fprintf(stderr, "Failed to set ciphersuites\n");
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

int main() {
    // 第一部分: 作为服务器接受Client连接
    SSL_CTX *server_ctx = create_server_context();
    configure_server_context(server_ctx);
    
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    // 创建服务器套接字
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(CLIENT_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    
    bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr));
    listen(server_fd, 5);
    
    printf("Verifier listening for client on port %d\n", CLIENT_PORT);
    
    // 接受客户端连接
    client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
    SSL *client_ssl = SSL_new(server_ctx);
    SSL_set_fd(client_ssl, client_fd);
    
    // 设置消息回调
    SSL_set_msg_callback(client_ssl, msg_callback);
    SSL_set_msg_callback_arg(client_ssl, NULL);
    
    // 执行TLS握手
    if (SSL_accept(client_ssl)) {
        printf("Accepted client connection with cipher: %s\n", SSL_get_cipher(client_ssl));
        
        // // 接收客户端消息
        char buf[BUFFER_SIZE];
        int bytes = SSL_read(client_ssl, buf, sizeof(buf));
        if (bytes > 0) {
            buf[bytes] = '\0';
            printf("Received from client: %s\n", buf);
            
            // 回复客户端
            const char *response = "Hello from Verifier!";
            SSL_write(client_ssl, response, strlen(response));
        }
        // 启动线程保持client连接（实际代码需添加线程处理）
        // keep_connection_alive(client_ssl, "Client-Verifier");
    } else {
        ERR_print_errors_fp(stderr);
    }
    
    // 关闭客户端连接
    SSL_shutdown(client_ssl);
    SSL_free(client_ssl);
    close(client_fd);
    close(server_fd);
    
    // 第二部分: 作为客户端连接Server
    SSL_CTX *client_ctx = create_client_context();
    SSL_CTX_set_min_proto_version(client_ctx, TLS1_3_VERSION);
    
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr2;
    memset(&server_addr2, 0, sizeof(server_addr2));
    server_addr2.sin_family = AF_INET;
    server_addr2.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr2.sin_addr);
    
    if (connect(server_sock, (struct sockaddr*)&server_addr2, sizeof(server_addr2))) {
        perror("Failed to connect to server");
        exit(EXIT_FAILURE);
    }
    
    SSL *server_ssl = SSL_new(client_ctx);
    SSL_set_fd(server_ssl, server_sock);
    
    // 执行TLS握手
    if (SSL_connect(server_ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        printf("Connected to server with %s\n", SSL_get_cipher(server_ssl));
        // 保持server连接
        // keep_connection_alive(server_ssl, "Verifier-Server");
        if (finished_msg_len > 0) {
            // 构造发送消息: 前缀 + FinV内容
            char send_buf[BUFFER_SIZE];
            strcpy(send_buf, "FinV content:");
            memcpy(send_buf + strlen("FinV content:"), finished_msg, finished_msg_len);
            size_t total_len = strlen("FinV content:") + finished_msg_len;
            
            // 发送给Server
            SSL_write(server_ssl, send_buf, total_len);
            printf("Sent FinV content to server\n");
            
            // 接收服务器响应
            char buf[BUFFER_SIZE];
            int bytes = SSL_read(server_ssl, buf, sizeof(buf));
            if (bytes > 0) {
                buf[bytes] = '\0';
                const unsigned char *response = (const unsigned char *)buf;
                size_t response_len = bytes;
                printf("response message (%u bytes):\n", bytes);
                for (size_t i = 0; i < response_len; i++) {
                    printf("%02X ", response[i]);
                    if ((i + 1) % 16 == 0) printf("\n");
                }
                printf("\n");
            }
        } else {
            printf("No FinV content to send\n");
        }
    }
    
    // 清理资源
    SSL_shutdown(server_ssl);
    SSL_free(server_ssl);
    SSL_CTX_free(server_ctx);
    SSL_CTX_free(client_ctx);
    close(server_sock);
    
    return 0;
}