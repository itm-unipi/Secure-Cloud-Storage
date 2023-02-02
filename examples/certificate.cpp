#include <iostream> 
#include <string>
#include <stdio.h> // for fopen(), etc.
#include <limits.h> // for INT_MAX
#include <string.h> // for memset()
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h> // for error descriptions

using namespace std;

int main() {
    int ret; // used for return values

    // load the CA's certificate:
    string ca_certificate_filename = "resources/certificates/CA_certificate.pem";
    FILE* ca_certicate_file = fopen(ca_certificate_filename.c_str(), "r");
    if (!ca_certicate_file) { 
        cerr << "Error: cannot open file '" << ca_certicate_file << "' (missing?)" << endl; 
        exit(1); 
    }

    X509* ca_certificate = PEM_read_X509(ca_certicate_file, NULL, NULL, NULL);
    
    fclose(ca_certicate_file);
    if (!ca_certificate) { 
        cerr << "Error: PEM_read_X509 returned NULL" << endl; 
        exit(1); 
    }

    // load the CRL:
    string crl_filename = "resources/certificates/CA_crl.pem";
    FILE* crl_file = fopen(crl_filename.c_str(), "r");
    if (!crl_file) { 
        cerr << "Error: cannot open file '" << crl_filename << "' (missing?)" << endl; 
        exit(1); 
    }

    X509_CRL* crl = PEM_read_X509_CRL(crl_file, NULL, NULL, NULL);
    
    fclose(crl_file);
    if (!crl) { 
        cerr << "Error: PEM_read_X509_CRL returned NULL" << endl; 
        exit(1); 
    }

    // build a store with the CA's certificate and the CRL:
    X509_STORE* store = X509_STORE_new();
    if (!store) { 
        cerr << "Error: X509_STORE_new returned NULL\n" << ERR_error_string(ERR_get_error(), NULL) << endl; 
        exit(1); 
    }

    ret = X509_STORE_add_cert(store, ca_certificate);
    if (ret != 1) { 
        cerr << "Error: X509_STORE_add_cert returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << endl; 
        exit(1); 
    }

    ret = X509_STORE_add_crl(store, crl);
    if (ret != 1) { 
        cerr << "Error: X509_STORE_add_crl returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << endl; 
        exit(1); 
    }

    ret = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
    if (ret != 1) { 
        cerr << "Error: X509_STORE_set_flags returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << endl; 
        exit(1); 
    }

    // load the peer's certificate:
    string certificate_filename = "resources/certificates/Server_certificate.pem";
    FILE* certificate_file = fopen(certificate_filename.c_str(), "r");
    if (!certificate_file) { 
        cerr << "Error: cannot open file '" << certificate_file << "' (missing?)" << endl; 
        exit(1); 
    }

    X509* certificate = PEM_read_X509(certificate_file, NULL, NULL, NULL);
    fclose(certificate_file);
    if (!certificate) { 
        cerr << "Error: PEM_read_X509 returned NULL" << endl; 
        exit(1); 
    }
    
    // verify the certificate:
    X509_STORE_CTX* certificate_verify_ctx = X509_STORE_CTX_new();
    if (!certificate_verify_ctx) { 
        cerr << "Error: X509_STORE_CTX_new returned NULL\n" << ERR_error_string(ERR_get_error(), NULL) << endl; 
        exit(1); 
    }

    ret = X509_STORE_CTX_init(certificate_verify_ctx, store, certificate, NULL);
    if (ret != 1) { 
        cerr << "Error: X509_STORE_CTX_init returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << endl; 
        exit(1); 
    }

    ret = X509_verify_cert(certificate_verify_ctx);
    if (ret != 1) { 
        cerr << "Error: X509_verify_cert returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << endl; 
        exit(1); 
    }

    // print the successful verification to screen:
    char* subject_name = X509_NAME_oneline(X509_get_subject_name(certificate), NULL, 0);
    char* issuer_name = X509_NAME_oneline(X509_get_issuer_name(certificate), NULL, 0);
    cout << "Certificate of \"" << subject_name << "\" (released by \"" << issuer_name << "\") verified successfully" << endl;
    free(subject_name);
    free(issuer_name);

    // get the public key
    EVP_PKEY* public_key = X509_get_pubkey(certificate);
    cout << "PUBLIC KEY: " << public_key << endl;
    EVP_PKEY_free(public_key);

    // deallocate data:
    X509_free(certificate);
    X509_STORE_free(store);
    X509_free(ca_certificate);
    X509_CRL_free(crl);
    X509_STORE_CTX_free(certificate_verify_ctx);

    return 0;
}
