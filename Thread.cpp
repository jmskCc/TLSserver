#include "head.h"

HANDLE g_hEvent;			//事件内核对象
int clnt_cnt = 0;			//统计套接字
struct ClientSSLAndSocket clntSSL[MAX_CLNT];	//管理套接字
HANDLE hThread[MAX_CLNT];	//管理线程
void error_handling(const char* msg)
{
	printf("%s\n", msg);
	WSACleanup();
	exit(1);
}

DWORD WINAPI ThreadProc(LPVOID lpParam)
{
	int clnt_sock = ((ClientSSLAndSocket*)lpParam)->clientfd;
	SSL* clnt_ssl = ((ClientSSLAndSocket*)lpParam)->ssl;
	int str_len = 0;
	int i;
	char msg[MAX_BUF_SIZE];
	if (SSL_accept(clnt_ssl) == -1)
	{
		printf("SSL_accept failed\n");
		goto END_OF_THREAD;
	}
	else {
		if (CheckCert(clnt_ssl) == -1) {
			goto END_OF_THREAD;
		}
		
	}
	
	while ((str_len = SSL_read(clnt_ssl, msg, sizeof(msg))) > 0)
	{
		send_msg(msg, str_len);
		printf("群发成功\n");
	}
	
	printf("客户端退出:%d\n", GetCurrentThreadId());
	
	//退出线程等待内核事件对象状态触发
	END_OF_THREAD:
	WaitForSingleObject(g_hEvent, INFINITE);
	for (i = 0; i < clnt_cnt; i++)
	{
		if (clnt_sock == clntSSL[i].clientfd)
		{
			while (i++ < clnt_cnt - 1)
				clntSSL[i] = clntSSL[i + 1];
			break;
		}
	}
	clnt_cnt--;
	SetEvent(g_hEvent);		//设置触发
	if (clnt_ssl) {
		SSL_shutdown(clnt_ssl);
		SSL_free(clnt_ssl);
	}
	closesocket(clnt_sock);
	return NULL;
}

void send_msg(char* msg, int len)
{
	WaitForSingleObject(g_hEvent, INFINITE);
	for (int i = 0; i < clnt_cnt; i++)
		SSL_write(clntSSL[i].ssl,msg , len);
	SetEvent(g_hEvent);		//设置触发
}