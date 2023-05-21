#include "head.h"

int CheckCert(SSL* ssl) {
    X509* cert;
    char* line;
    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL) {
        printf("����֤����Ϣ:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("֤��: %s\n", line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0); 
        printf("�䷢��: %s\n", line);
        X509_free(cert);
    }
    else {
        printf("��֤����Ϣ��\n");
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
        return -1;
    }
}