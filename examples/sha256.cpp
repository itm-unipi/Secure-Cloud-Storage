#include <iostream>
#include <openssl/evp.h>
using namespace std;

int main() {

    char msg[] = "Lorem ipsum dolor sit amet.";

    // ----------------- CALCULATION -----------------

    unsigned char* digest;
    unsigned int digestlen;
    EVP_MD_CTX* ctx;

    /* Buffer allocation for the digest */
    digest = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));

    /* Context allocation */
    ctx = EVP_MD_CTX_new();

    /* Hashing (initialization + single update + finalization */
    EVP_DigestInit(ctx, EVP_sha256());
    EVP_DigestUpdate(ctx, (unsigned char*)msg, sizeof(msg));
    EVP_DigestFinal(ctx, digest, &digestlen);

    cout << "HASH_1: " << digest << endl;

    /* Context deallocation */
    EVP_MD_CTX_free(ctx);

    // ----------------- VERIFICATION -----------------

    /* ...receives the message and the message digest... */
    unsigned char* digest_2;
    unsigned int digestlen_2;
    EVP_MD_CTX* ctx_2;

    /* Buffer allocation for the digest */
    digest_2 = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));

    /* Context allocation */
    ctx_2 = EVP_MD_CTX_new();

    /* Hashing (initialization + single update + finalization */
    EVP_DigestInit(ctx_2, EVP_sha256());
    EVP_DigestUpdate(ctx_2, (unsigned char*)msg, sizeof(msg));
    EVP_DigestFinal(ctx_2, digest_2, &digestlen_2);

    cout << "HASH_2: " << digest << endl;

    /* Context deallocation */
    EVP_MD_CTX_free(ctx_2);

    if(CRYPTO_memcmp(digest_2, digest, EVP_MD_size(EVP_sha256())) == 0)
        cout << "HASH uguali" << endl;
    else
        cerr << "HASH diversi" << endl;

    return 0;
}