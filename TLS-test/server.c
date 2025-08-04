#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/aes.h>

#define PORT 4433
#define BUFFER_SIZE 1024

static const unsigned char* KEY=(const unsigned char*)"0123456789ABCDEF0123456789ABCDEF"; // 32字节密钥(256位)
static unsigned char finished_msg[BUFFER_SIZE];
static size_t finished_msg_len = 0;

// AES-ECB加密函数
void aes_ecb_encrypt(const unsigned char *plaintext, size_t len, 
                    const unsigned char *key, unsigned char *ciphertext) {
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 256, &aes_key); // 256位密钥
    
    // ECB模式需要数据是16字节的倍数，不足需要填充
    size_t padded_len = (len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE * AES_BLOCK_SIZE;
    unsigned char padded_data[padded_len];
    memcpy(padded_data, plaintext, len);
    memset(padded_data + len, 0, padded_len - len); // 零填充
    
    for (size_t i = 0; i < padded_len; i += AES_BLOCK_SIZE) {
        AES_encrypt(padded_data + i, ciphertext + i, &aes_key);
    }
}

SSL_CTX* create_context() {
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("SSL_CTX_new failed");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_context(SSL_CTX *ctx) {
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
    SSL_CTX *ctx;
    int sockfd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    // 初始化 OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // 创建 SSL 上下文
    ctx = create_context();
    configure_context(ctx);

    // 创建 TCP 套接字
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr));
    listen(sockfd, 5);

    printf("TLS 1.3 Server listening on port %d\n", PORT);

    while (1) {
        client_fd = accept(sockfd, (struct sockaddr*)&client_addr, &client_len);
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);

        // 执行 TLS 握手
        if (SSL_accept(ssl)) {
            printf("TLS 1.3 handshake successful\n");
            
            // 接收数据
            char buf[BUFFER_SIZE];
            int bytes = SSL_read(ssl, buf, sizeof(buf));
            if (bytes > 0) {
                buf[bytes] = '\0';
                
                // 检查是否是FinV内容
                if (strstr(buf, "FinV content:")) {
                    printf("Received FinV content from verifier\n");
                    
                    // 提取Finished消息
                    const unsigned char *content = (const unsigned char *)(buf + strlen("FinV content:"));
                    size_t content_len = bytes - strlen("FinV content:");

                    // 保存Finished消息
                    memcpy(finished_msg, content, content_len);
                    finished_msg_len = content_len;
                    
                    // 打印原始消息
                    printf("Original Finished message (%zu bytes):\n", finished_msg_len);
                    for (size_t i = 0; i < finished_msg_len; i++) {
                        printf("%02X ", finished_msg[i]);
                        if ((i + 1) % 16 == 0) printf("\n");
                    }
                    printf("\n");

                    // AES-ECB加密
                    unsigned char ciphertext[BUFFER_SIZE] = {0};
                    aes_ecb_encrypt(finished_msg, finished_msg_len, 
                                   (const unsigned char *)KEY, ciphertext);
                    
                    // 计算密文长度(填充到16字节倍数)
                    size_t cipher_len = (finished_msg_len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE * AES_BLOCK_SIZE;
                    
                    // 打印密文
                    printf("AES-ECB Ciphertext (%zu bytes):\n", cipher_len);
                    for (size_t i = 0; i < cipher_len; i++) {
                        printf("%02X ", ciphertext[i]);
                        if ((i + 1) % 16 == 0) printf("\n");
                    }
                    printf("\n");

                    // 发送加密后的数据
                    SSL_write(ssl, ciphertext, cipher_len);
                    printf("Sent encrypted FinV content back to verifier\n");
                } else {
                    printf("Received: %s\n", buf);
                    const char *response = "Hello from Server!";
                    SSL_write(ssl, response, strlen(response));
                }
            }
        } else {
            ERR_print_errors_fp(stderr);
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
    }

    SSL_CTX_free(ctx);
    close(sockfd);
    return 0;
}