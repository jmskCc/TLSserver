#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <winsock2.h>

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"libcrypto.lib")
#pragma comment(lib,"libssl.lib")

#define MAX_BUF_SIZE 2048
#define SERVER_PORT 8080
#define SERVER_CERT "C:\\Users\\64515\\Desktop\\毕业设计\\证书\\server\\server.crt"
#define SERVER_KEY "C:\\Users\\64515\\Desktop\\毕业设计\\证书\\server\\server.key"
#define CA_CERT "C:\\Users\\64515\\Desktop\\毕业设计\\证书\\ca.crt"

int CheckCert(SSL* ssl);
int main(int argc, char* argv[])
{
    char buf[MAX_BUF_SIZE];
    WSADATA wsaData;
    int err = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (err != 0) {
        printf("WSAStartup failed with error: %d\n", err);
        return -1;
    }
   
    /*ssl初始化*/
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx)
    {
        ERR_print_errors_fp(stdout);
        printf("SSL_CTX_new failed\n");
        return -1;
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    if (SSL_CTX_load_verify_locations(ctx, CA_CERT, NULL) <= 0)
    {
        printf("SSL_CTX_load_verify_locations failed\n");
        ERR_print_errors_fp(stdout);
        return -1;
    }

    if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT, SSL_FILETYPE_PEM) <= 0)
    {
        printf("SSL_CTX_use_certificate_file failed\n");
        ERR_print_errors_fp(stdout);
        return -1;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY, SSL_FILETYPE_PEM) <= 0)
    {
        printf("SSL_CTX_use_PrivateKey_file failed\n");
        ERR_print_errors_fp(stdout);
        return -1;
    }

    if (!SSL_CTX_check_private_key(ctx))
    {
        printf("Private key does not match the certificate public key\n");
        ERR_print_errors_fp(stdout);
        return -1;
    }

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == INVALID_SOCKET)
    {
        printf("socket failed\n");
        return -1;
    }
    else
    {
        printf("Creat socket succes\n");
    }

    struct sockaddr_in server_addr, client_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    memset(&client_addr, 0, sizeof(client_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR)
    {
        printf("bind failed\n");
        return -1;
    }

    if (listen(sockfd, 5) == SOCKET_ERROR)
    {
        printf("listen failed\n");
        return -1;
    }

    for(;;)
    {
        printf("Waiting for client connection...\n");
        int len = sizeof(client_addr);
        int clientfd = accept(sockfd, (struct sockaddr*)&client_addr, &len);
        if (clientfd == INVALID_SOCKET)
        {
            printf("accept failed\n");
            return -1;
        }
        else {
            printf("server: got connection from %s, port %d, socket %d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), clientfd);
        }

        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, clientfd);
        if (SSL_accept(ssl) == -1)
        {
            printf("SSL_accept failed\n");
            goto Continue;
        }
        else {
            if (CheckCert(ssl) == -1) {
                goto Continue;
            }
        }

        for(;;)
        {
            memset(buf, 0, MAX_BUF_SIZE);
            int ret = SSL_read(ssl, buf, MAX_BUF_SIZE);
            if (ret <= 0) {
                break;
            }

            buf[ret] = '\0';
            printf("Received message: %s\n", buf);
            memset(buf, 0, MAX_BUF_SIZE);
            printf("Server enter message to send (q to quit):\n");
            fgets(buf, MAX_BUF_SIZE, stdin);
            buf[strlen(buf) - 1] = 0;
            if (strcmp(buf, "q") == 0) {
                goto Continue;
            }
            SSL_write(ssl, buf, (strlen(buf)+1));

        }

    Continue:
        if (ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        closesocket(clientfd);
    }

    SSL_CTX_free(ctx);
    closesocket(sockfd);
    WSACleanup();
    return 0;
}

int CheckCert(SSL* ssl) {
    X509* cert;
    char* line;
    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL) {
        printf("数字证书信息:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("证书: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("颁发者: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else {
        printf("无证书信息！\n");
        return -1;
    }
    // SSL_get_verify_result()是重点，SSL_CTX_set_verify()只是配置启不启用并没有执行认证，调用该函数才会真证进行证书认证
    // 如果验证不通过，那么程序抛出异常中止连接
    if (SSL_get_verify_result(ssl) == X509_V_OK) {
        printf("证书验证通过\n");
        return 1;
    }
    else
    {
        printf("证书验证不通过\n");
        return -1;
    }
    return -1;
}