#include "head.h"

#define MAX_BUF_SIZE 2048
#define SERVER_PORT 443
#define SERVER_CERT "C:\\Users\\64515\\Desktop\\毕业设计\\证书\\server\\server.crt"

int main(int argc, char* argv[])
{
    char buf[MAX_BUF_SIZE];
    char addr[MAX_BUF_SIZE];
    EVP_PKEY* pkey;
    X509* cert;
    WSADATA wsaData;
    int* err = (int*)malloc(sizeof(int));
    *err = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (*err != 0) {
        printf("WSAStartup failed with error: %d\n", *err);
        return -1;
    }
    free(err);

    /*ssl初始化*/
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    CRYPTO_secure_malloc_init(32768, 1);

    SSL_CTX* ctx = SSL_CTX_new(TLSv1_2_server_method());
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

    printf("(服务器）请输入P12证书地址\n");
    scanf("%s", addr);
    if (InitialP12(addr, &pkey, &cert) != 1) {
        printf("InitialP12 failed\n");
    }

    if (SSL_CTX_use_certificate(ctx, cert) <= 0)//加载证书
    {
        printf("SSL_CTX_use_certificate failed\n");
        ERR_print_errors_fp(stdout);
        return -1;
    }

    if (SSL_CTX_use_PrivateKey(ctx, pkey) <= 0)//加载私钥
    {
        printf("SSL_CTX_use_PrivateKey failed\n");
        ERR_print_errors_fp(stdout);
        return -1;
    }

    if (!SSL_CTX_check_private_key(ctx))//检查证书私钥一致性
    {
        printf("Private key does not match the certificate public key\n");
        ERR_print_errors_fp(stdout);
        return -1;
    }

    /*
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
    */
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

    long options = SSL_CTX_get_options(ctx);
    options |= SSL_OP_NO_TICKET;
    SSL_CTX_set_options(ctx, options);

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

    for (;;)
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

        for (;;)
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
            SSL_write(ssl, buf, (strlen(buf) + 1));

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
    EVP_PKEY_free(pkey);
    X509_free(cert);
    CRYPTO_secure_malloc_done();
    return 0;
}
