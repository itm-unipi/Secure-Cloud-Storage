#ifndef _CERTIFICATESTORE_H
#define _CERTIFICATESTORE_H

#define CA_CERTIFICATE_FILENAME "resources/certificates/CA_certificate.pem"
#define CRL_FILENAME "resources/certificates/CA_crl.pem"

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

    bool verify(string certificate_filename);
    EVP_PKEY* getPublicKey(string certificate_filename);

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
