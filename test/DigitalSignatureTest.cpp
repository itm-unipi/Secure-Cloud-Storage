#include <iostream>
#include <openssl/pem.h>

#include "../src/DigitalSignature.h"

using namespace std;

int main() {
    /*..retrieve private key..*/
    unsigned char msg[] = "Lorem ipsum dolor sit amet.";

    // --------------------- key generations ---------------------

    EVP_PKEY *private_key = NULL;
    private_key = EVP_PKEY_new();
    if (!private_key) {
        // Gestione degli errori
        return -1;
    }

    RSA *rsa = RSA_generate_key(4096, RSA_F4, NULL, NULL);
    if (!EVP_PKEY_assign_RSA(private_key, rsa)) {
        // Gestione degli errori
        return -1;
    }

    // Estrarre la chiave pubblica
    EVP_PKEY *public_key = EVP_PKEY_new();
    if (!EVP_PKEY_assign_RSA(public_key, EVP_PKEY_get1_RSA(private_key))) {
        // Gestione degli errori
        return -1;
    }

    cout << "Private key: " << private_key << endl;
    cout << "Public key: " << public_key << endl;

    // -----------------------------------------------------------

    unsigned char* signature;
    unsigned int signature_size;
    
    DigitalSignature::generate(msg, sizeof(msg), signature, signature_size, private_key);

    cout << "Signature size: " << signature_size << endl;

    bool res = DigitalSignature::verify(msg, sizeof(msg), signature, signature_size, public_key);
    
    if (res)
        cout << "Firma valida" << endl;
    else
        cerr << "Firma invalida" << endl;

    delete[] signature;
    EVP_PKEY_free(private_key);
    EVP_PKEY_free(public_key);

    return 0;
}