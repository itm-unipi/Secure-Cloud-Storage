#include <iostream>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>

#include "CertificateStore.h"

using namespace std;

// initialize the singleton
CertificateStore* CertificateStore::m_certificate_store_instance = nullptr;

CertificateStore::CertificateStore() {

    string ca_certificate_filename = CA_CERTIFICATE_FILENAME;
    string crl_filename = CRL_FILENAME;

    // ----------------- CA certificate loading -----------------

    FILE* ca_certicate_file = fopen(ca_certificate_filename.c_str(), "r");
    if (!ca_certicate_file) { 
        cerr << "[-] Failed to open CA certificate file" << endl; 
        return;
    }

    X509* ca_certificate = PEM_read_X509(ca_certicate_file, NULL, NULL, NULL);
    
    fclose(ca_certicate_file);
    if (!ca_certificate) { 
        cerr << "[-] Failed to load CA certificate" << endl; 
        return;
    }
    
    // ---------------------- CRL loading -----------------------

    FILE* crl_file = fopen(crl_filename.c_str(), "r");
    if (!crl_file) { 
        cerr << "[-] Failed to open CRL file" << endl; 
        return; 
    }

    X509_CRL* crl = PEM_read_X509_CRL(crl_file, NULL, NULL, NULL);
    
    fclose(crl_file);
    if (!crl) { 
        cerr << "[-] Failed to load CRL" << endl; 
        return; 
    }
    
    // --------------------- STORE building ---------------------

    m_store = X509_STORE_new();
    if (!m_store) { 
        cerr << "[-] Failed to create the store" << endl; 
        return; 
    }

    int ret = X509_STORE_add_cert(m_store, ca_certificate);
    if (ret != 1) { 
        cerr << "[-] Failed to add CA certificate to the store" << endl; 
        return; 
    }

    ret = X509_STORE_add_crl(m_store, crl);
    if (ret != 1) { 
        cerr << "[-] Failed to add CRL to the store" << endl; 
        return; 
    }

    ret = X509_STORE_set_flags(m_store, X509_V_FLAG_CRL_CHECK);
    if (ret != 1) { 
        cerr << "[-] Failed set the store flags" << endl; 
        return;
    }
    
    // ----------------------------------------------------------

    X509_free(ca_certificate);
    X509_CRL_free(crl);
}

CertificateStore::~CertificateStore() {
    
    X509_STORE_free(m_store);
}

bool CertificateStore::verify(string certificate_filename) {

    FILE* certificate_file = fopen(certificate_filename.c_str(), "r");
    if (!certificate_file) { 
        cerr << "[-] Failed to open certificate" << endl; 
        return false; 
    }

    X509* certificate = PEM_read_X509(certificate_file, NULL, NULL, NULL);
    fclose(certificate_file);
    if (!certificate) { 
        cerr << "[-] Failed read certificate" << endl; 
        return false;
    }
    
    X509_STORE_CTX* certificate_verify_ctx = X509_STORE_CTX_new();
    if (!certificate_verify_ctx) { 
        cerr << "[-] Failed to create the verification context" << endl;
        X509_free(certificate); 
        return false;
    }

    int ret = X509_STORE_CTX_init(certificate_verify_ctx, m_store, certificate, NULL);
    if (ret != 1) { 
        cerr << "[-] Failed to initialize the verification context" << endl; 
        X509_free(certificate);
        return false;
    }

    ret = X509_verify_cert(certificate_verify_ctx);
    X509_free(certificate);
    if (ret != 1) { 
        cerr << "[-] Certificate validation failed" << endl; 
        return false;
    }

    X509_STORE_CTX_free(certificate_verify_ctx);
    return true;
}

EVP_PKEY* CertificateStore::getPublicKey(string certificate_filename) {

    FILE* certificate_file = fopen(certificate_filename.c_str(), "r");
    if (!certificate_file) { 
        cerr << "[-] Failed to open certificate" << endl; 
        return nullptr; 
    }

    X509* certificate = PEM_read_X509(certificate_file, NULL, NULL, NULL);
    fclose(certificate_file);
    if (!certificate) { 
        cerr << "[-] Failed read certificate" << endl; 
        return nullptr;
    }

    EVP_PKEY* public_key = X509_get_pubkey(certificate);
    X509_free(certificate);

    return public_key;
}
