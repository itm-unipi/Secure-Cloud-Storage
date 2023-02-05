#include <iostream>
#include <cstring>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "../src/security/CertificateStore.h"

using namespace std;

int main() {

    string certificate_files[] = { "Biagio_certificate.pem", "Gianluca_certificate.pem", "Matteo_certificate.pem" };
    string pem_files[] = { "biagio_key.pem", "gianluca_key.pem", "matteo_key.pem" };

    for (int i = 0; i < 3; ++i) {

        // read private key in clear from pem file
        string filepath = "resources/certificates/" + certificate_files[i];
        CertificateStore* certificate_store = CertificateStore::getStore();
        X509* certificate = certificate_store->load(filepath);

        // extract the public key
        EVP_PKEY* public_key = certificate_store->getPublicKey(certificate);

        // save the key in the file
        string filepath2 = "resources/public_keys/" + pem_files[i];
        BIO *bp = BIO_new_file(filepath2.c_str(), "w");
        PEM_write_bio_PUBKEY(bp, public_key);

        BIO_free(bp);
        EVP_PKEY_free(public_key);
    }

    return 0;
}