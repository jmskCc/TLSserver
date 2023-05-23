#include "head.h"


int main(int argc, char* argv[])
{
    char addr[MAX_BUF_SIZE];
    EVP_PKEY* pkey;
    X509* cert;
    SSL_CTX* ctx;
    WSADATA wsaData;
    int flag;
    int* err = (int*)malloc(sizeof(int));
    *err = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (*err != 0) {
        printf("WSAStartup failed with error: %d\n", *err);
        return -1;
    }
    free(err);

    // 创建一个自动重置的事件内核对象
    g_hEvent = CreateEvent(NULL, FALSE, TRUE, NULL);


    /*ssl初始化*/
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    CRYPTO_secure_malloc_init(32768, 1);

   /*(SSLInitial(ctx, &pkey, &cert) != 1) {
        printf("SSLInitial failed\n");
        return -1;
    }
    */
    ctx = SSL_CTX_new(TLSv1_2_server_method());
    if (!ctx)
    {
        ERR_print_errors_fp(stdout);
        printf("SSL_CTX_new failed\n");
        return -1;
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    for (;;) {
        printf("(服务器）请输入根证书地址\n");
        scanf("%s", addr);
        if (SSL_CTX_load_verify_locations(ctx, addr, NULL) <= 0)
        {
            printf("SSL_CTX_load_verify_locations failed\n");
            ERR_print_errors_fp(stdout);
            continue;
        }
        else
        {
            break;
        }
    }
    memset(addr, 0, MAX_BUF_SIZE);
    for (;;) {
        printf("(服务器）请输入P12证书地址\n");
        scanf("%s", addr);
        if (InitialP12(addr, &pkey, &cert) != 1) {
            printf("InitialP12 failed\n");
            continue;
        }
        else
        {
            flag = X509_check_purpose(cert, X509_PURPOSE_SSL_SERVER, 0);
            if ( flag == 0) {
                printf("该证书不能用于服务器\n");
                continue;
            }
            else if(flag == -1)
            {
                printf("证书用途验证错误\n");
                continue;
            }
            else if (flag == 1) {
                break;
            }
        }
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
        error_handling("Failed bind()");
        return -1;
    }

    if (listen(sockfd, MAX_CLNT) == SOCKET_ERROR)
    {
        printf("listen failed\n");
        return -1;
    }

    DWORD dwThreadId;	/*线程ID*/
    int clientfd;
    int len = sizeof(client_addr);
    
    system("cls");
    printf("Waiting for client connection...\n");
    for (;;)
    {
        clientfd = accept(sockfd, (struct sockaddr*)&client_addr, &len);
        printf("Waiting for client connection...\n");
        if (clientfd == INVALID_SOCKET)
        {
            printf("accept failed\n");
            continue;
        }
        
        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, clientfd);

        WaitForSingleObject(g_hEvent, INFINITE);

        clntSSL[clnt_cnt].clientfd = clientfd;
        clntSSL[clnt_cnt].ssl = ssl;
        hThread[clnt_cnt] = CreateThread(
            NULL,		// 默认安全属性
            NULL,		// 默认堆栈大小
            ThreadProc,	// 线程入口地址（执行线程的函数）
            (void*)&clntSSL[clnt_cnt],		// 传给函数的参数
            0,		// 指定线程立即运行
            &dwThreadId);
        clnt_cnt++;
        SetEvent(g_hEvent);
        printf("server: ThreadID %d got connection from %s, port %d, socket %d\n", dwThreadId,inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), clientfd);
        /*
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
        */
    //Continue:
        
    }
    WaitForMultipleObjects(clnt_cnt, hThread, true, INFINITE);

    for (int i = 0; i < clnt_cnt; i++)
    {
        CloseHandle(hThread[i]);
    }

    SSL_CTX_free(ctx);
    closesocket(sockfd);
    WSACleanup();
    EVP_PKEY_free(pkey);
    X509_free(cert);
    CRYPTO_secure_malloc_done();
    return 0;
}
