#pragma once
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/asn1t.h>
#include <openssl/pkcs12.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"libcrypto.lib")
#pragma comment(lib,"libssl.lib")

#define MAX_BUF_SIZE 2048
#define MAX_CLNT 256
#define SERVER_PORT 446
#define CA_CERT "C:/Users/64515/Desktop/毕业设计/证书/ca.crt"

struct ClientSSLAndSocket
{
	SSL* ssl;
	int clientfd;
};

extern HANDLE g_hEvent;			/*事件内核对象*/
extern int clnt_cnt;			//统计套接字
extern ClientSSLAndSocket clntSSL[MAX_CLNT];	//管理套接字
extern HANDLE hThread[MAX_CLNT];	//管理线程

void error_handling(const char* msg);		/*错误处理函数*/
DWORD WINAPI ThreadProc(LPVOID lpParam);	/*线程执行函数*/
void send_msg(char* msg, int len);			/*消息发送函数*/
int SSLInitial(SSL_CTX* ctx, EVP_PKEY** pkey, X509** cert);
int CheckCert(SSL* ssl);
void GetPassword(char* password);
int InitialP12(char* addr, EVP_PKEY** pkey_s, X509** cert_s);