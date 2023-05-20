#include "head.h"

char* GetCNFormCert(X509* cert) {
    if (!cert) {
        return NULL;
    }

    // ��ȡ��������
    X509_NAME* subject_name = X509_get_subject_name(cert);
    if (!subject_name) {
        return NULL;
    }

    // ����CN��Ŀ
    int idx = X509_NAME_get_index_by_NID(subject_name, NID_commonName, -1);
    if (idx == -1) {
        return NULL;
    }
        // ��ȡCN��Ŀ
        X509_NAME_ENTRY* cn_entry = X509_NAME_get_entry(subject_name, idx);
    if (!cn_entry) {
        return NULL;
    }

    // ��ȡASN1�ַ���
    ASN1_STRING* cn_asn1 = X509_NAME_ENTRY_get_data(cn_entry);
    if (!cn_asn1) {
        return NULL;
    }

    // ��ASN1�ַ���ת��ΪC�ַ���
    char* cn_str = (char*)ASN1_STRING_data(cn_asn1);

    return cn_str;
}