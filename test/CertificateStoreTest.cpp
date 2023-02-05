#include <iostream>
#include <openssl/pem.h>

#include "../src/security/CertificateStore.h"
// #include "../src/security/DigitalSignature.h"

using namespace std;

int main() {

    EVP_PKEY* private_key;
    FILE* private_key_file;

    // load private key from PEM file
    private_key_file = fopen("resources/private_keys/server_key.pem", "rb");
    private_key = PEM_read_PrivateKey(private_key_file, NULL, NULL, NULL);
    fclose(private_key_file); 
    cout << "CHIAVE PRIVATA: " << private_key << endl;   

    // load the certificate
    string certificate_filename = "resources/certificates/Server_certificate.pem";
    CertificateStore* certificate_store = CertificateStore::getStore();
    X509* certificate = certificate_store->load(certificate_filename);
    // cout << "\nCERTIFICATO: " << endl;
    // X509_print_fp(stdout, certificate);

    // verify certificate
    if (!certificate_store->verify(certificate)) {
        cerr << "Certificato non valido" << endl;
        X509_free(certificate);
        return -1;
    }
    cout << "\nCertificato valido" << endl;
    
    // load public key from certificate
    EVP_PKEY* public_key = certificate_store->getPublicKey(certificate);
    cout << "\nCHIAVE PUBBLICA: " << endl;
    // BIO_dump_fp(stdout, (const char*)public_key, 256);

    /*/ ------------------ Prova della Firma ------------------
    
    unsigned char msg[] = "Lorem ipsum dolor sit amet.";

    unsigned char* signature;
    unsigned int signature_size;
    
    DigitalSignature::generate(msg, sizeof(msg), signature, signature_size, private_key);

    cout << "Signature size: " << signature_size << endl;

    bool res = DigitalSignature::verify(msg, sizeof(msg), signature, signature_size, public_key);
    
    if (res)
        cout << "Firma valida" << endl;
    else
        cerr << "Firma invalida" << endl;
    
    // ------------------------------------------------------- */
    
    EVP_PKEY_free(public_key);
    EVP_PKEY_free(private_key);
    CertificateStore::deleteStore();

    return 0;
}