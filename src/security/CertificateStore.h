#ifndef _CERTIFICATESTORE_H
#define _CERTIFICATESTORE_H

#define CA_CERTIFICATE_FILENAME "resources/certificates/CA_certificate.pem"
#define CRL_FILENAME "resources/certificates/CA_crl.pem"
#define MAX_SERIALIZED_CERTIFICATE_SIZE 1500

#include <string>
#include <openssl/x509_vfy.h>
using namespace std;

class CertificateStore {

    X509_STORE* m_store;
    static CertificateStore* m_certificate_store_instance;

public:
    CertificateStore();
    CertificateStore(const CertificateStore&) = delete;
    ~CertificateStore();

    X509* load(string certificate_filename);
    bool verify(X509* certificate);
    EVP_PKEY* getPublicKey(X509* certificate);

    static int serializeCertificate(X509* certificate, uint8_t*& serialized_certificate, int& serialized_certificate_size);
    static X509* deserializeCertificate(uint8_t* serialized_certificate, int serialized_certificate_size);

    // -------------- Singleton management --------------

    static CertificateStore* getStore() {
        if (!m_certificate_store_instance)
            m_certificate_store_instance = new CertificateStore();
        return m_certificate_store_instance;
    }

    static void deleteStore() {
        if (m_certificate_store_instance)
            delete m_certificate_store_instance;
    }
    
    // --------------------------------------------------
};

#endif  // _CERTIFICATESTORE_H
