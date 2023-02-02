#include <iostream>
#include <openssl/evp.h>
#include <openssl/pem.h>
using namespace std;

int main() {
    /*..retrieve private key..*/
    char msg[] = "Lorem ipsum dolor sit amet.";

    // --------------------- key generations ---------------------

    EVP_PKEY *priv_key = NULL;
    priv_key = EVP_PKEY_new();
    if (!priv_key) {
        // Gestione degli errori
        return -1;
    }

    RSA *rsa = RSA_generate_key(4096, RSA_F4, NULL, NULL);
    if (!EVP_PKEY_assign_RSA(priv_key, rsa)) {
        // Gestione degli errori
        return -1;
    }

    // Estrarre la chiave pubblica
    EVP_PKEY *pub_key = EVP_PKEY_new();
    if (!EVP_PKEY_assign_RSA(pub_key, EVP_PKEY_get1_RSA(priv_key))) {
        // Gestione degli errori
        return -1;
    }

    cout << "Private key: " << priv_key << endl;
    cout << "Public key: " << pub_key << endl;

    // ------------------ signature calculation  -----------------

    unsigned char* signature;
    unsigned int signature_len;
    signature = (unsigned char*)malloc(EVP_PKEY_size(priv_key));
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    
    EVP_SignInit(ctx, EVP_sha256());
    EVP_SignUpdate(ctx, (unsigned char*)msg, sizeof(msg));
    EVP_SignFinal(ctx, signature, &signature_len, priv_key);

    EVP_MD_CTX_free(ctx);

    // cout << "Signature: " << signature << endl;
    
    // ----------------- signature verification  -----------------

    EVP_MD_CTX* ctx_2 = EVP_MD_CTX_new();

    EVP_VerifyInit(ctx_2, EVP_sha256());
    EVP_VerifyUpdate(ctx_2, (unsigned char*)msg, sizeof(msg));
    int res = EVP_VerifyFinal(ctx_2, signature, signature_len, pub_key);

    if (res == 1)
        cout << "Firma valida" << endl;
    else if (res == 0)
        cerr << "Firma invalida" << endl;
    else
        cerr << "Errore generico" << endl;

    EVP_MD_CTX_free(ctx_2);

    // -----------------------------------------------------------
    
    return 0;
}