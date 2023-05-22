#include "head.h"

int CheckCert(SSL* ssl) {
    X509* cert;
    char* line;
    cert = SSL_get_peer_certificate(ssl);
    int flag = X509_check_purpose(cert, X509_PURPOSE_SSL_CLIENT, 0);
    if (cert) {
        printf("����֤����Ϣ:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("֤��: %s\n", line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("�䷢��: %s\n", line);
        X509_free(cert);
    }
    else if (!cert) {
        printf("��֤����Ϣ��\n");
        return -1;
    }
    else if (flag == 0) {
        printf("��֤�鲻�����ڷ�����\n");
        return -1;
    }
    else if (flag == -1)
    {
        printf("֤����;��֤����\n");
        return -1;
    }
    else if (flag == 1) {
        return 1;
    }
    else {
        return -1;
    }

    long flag = SSL_get_verify_result(ssl);
    if (flag == X509_V_OK) {
        printf("֤����֤ͨ��\n");
        return 1;
    }
    else if(flag == X509_V_ERR_CERT_HAS_EXPIRED)
    {
        printf("֤���ѹ���\n");
        return -1;
    }
    else if (flag == X509_V_ERR_CERT_NOT_YET_VALID)
    {
        printf("֤��δ��Ч\n");
        return -1;
    }
    else if (flag == X509_V_ERR_CERT_UNTRUSTED)
    {
        printf("֤�鲻������\n");
        return -1;
    }
    else {
        printf("֤����֤ʧ��\n");
        return -1;
    }
}