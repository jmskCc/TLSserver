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

    if (SSL_get_verify_result(ssl) == X509_V_OK) {
        printf("֤����֤ͨ��\n");
        return 1;
    }
    else
    {
        printf("֤����֤��ͨ��\n");
        return -1;
    }
    return -1;
}