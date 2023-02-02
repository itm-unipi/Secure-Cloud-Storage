#include <openssl/pem.h>
#include <openssl/evp.h>

int main() {
    EVP_PKEY *pkey = NULL;
    pkey = EVP_PKEY_new();
    if (!pkey) {
        // Gestione degli errori
        return -1;
    }

    RSA *rsa = RSA_generate_key(4096, RSA_F4, NULL, NULL);
    if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
        // Gestione degli errori
        return -1;
    }

    // Salvare la chiave privata su un file
    FILE *fp = fopen("private_key.pem", "wb");
    if (!fp) {
        // Gestione degli errori
        return -1;
    }

    if (!PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL)) {
        // Gestione degli errori
        return -1;
    }

    fclose(fp);

    // Estrarre la chiave pubblica
    EVP_PKEY *pub_key = EVP_PKEY_new();
    if (!EVP_PKEY_assign_RSA(pub_key, EVP_PKEY_get1_RSA(pkey))) {
        // Gestione degli errori
        return -1;
    }

    // Salvare la chiave pubblica su un file
    fp = fopen("public_key.pem", "wb");
    if (!fp) {
        // Gestione degli errori
        return -1;
    }

    if (!PEM_write_PUBKEY(fp, pub_key)) {
        // Gestione degli errori
        return -1;
    }

    fclose(fp);

    // Deallocare la memoria
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(pub_key);

    return 0;
}
