#include <iostream>
#include <openssl/pem.h>

#include "../src/security/CertificateStore.h"
// #include "../src/security/DigitalSignature.h"

using namespace std;

int main() {

    EVP_PKEY* private_key;
    FILE* private_key_file;

    // load private key from PEM file
    private_key_file = fopen("resources/private_keys/Server_key.pem", "rb");
    private_key = PEM_read_PrivateKey(private_key_file, NULL, NULL, NULL);
    fclose(private_key_file); 
    cout << "CHIAVE PRIVATA: " << private_key << endl;   

    // verify certificate
    string certificate_filename = "resources/certificates/Server_certificate.pem";
    CertificateStore* certificate_store = CertificateStore::getStore();
    if (!certificate_store->verify(certificate_filename)) {
        cerr << "Certificato non valido" << endl;
        return -1;
    }
    cout << "Certificato valido" << endl;
    
    // load public key from certificate
    EVP_PKEY* public_key = certificate_store->getPublicKey(certificate_filename);
    cout << "CHIAVE PUBBLICA: " << public_key << endl;

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