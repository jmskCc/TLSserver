#include "head.h"

int SSLInitial(SSL_CTX* ctx, EVP_PKEY** pkey, X509** cert) {
    char addr[MAX_BUF_SIZE];
    ctx = SSL_CTX_new(TLSv1_2_server_method());
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
    if (InitialP12(addr, pkey, cert) != 1) {
        printf("InitialP12 failed\n");
    }

    if (SSL_CTX_use_certificate(ctx, *cert) <= 0)//加载证书
    {
        printf("SSL_CTX_use_certificate failed\n");
        ERR_print_errors_fp(stdout);
        return -1;
    }

    if (SSL_CTX_use_PrivateKey(ctx, *pkey) <= 0)//加载私钥
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
    return 1;
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
}