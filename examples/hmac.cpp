#include <iostream>
// #include <openssl/evp.h>
#include <openssl/hmac.h>
using namespace std;

int main() {

    char msg[] = "Lorem ipsum dolor sit amet.";
    unsigned char *key = (unsigned char *)"abcdefghijklmnopabcdefghijklmnop";
    int key_len = 32;

    // ----------------- CALCULATION -----------------

    unsigned char* digest;
    unsigned int digestlen;
    HMAC_CTX* ctx;

    /* Buffer allocation for the digest */
    digest = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));

    /* Context allocation */
    ctx = HMAC_CTX_new();

    /* Hashing (initialization + single update + finalization */
    HMAC_Init_ex(ctx, key, key_len, EVP_sha256(), nullptr);
    HMAC_Update(ctx, (unsigned char*)msg, sizeof(msg));
    HMAC_Final(ctx, digest, &digestlen);

    cout << "HMAC_1: " << digest << endl;

    /* Context deallocation */
    HMAC_CTX_free(ctx);

    // ----------------- VERIFICATION -----------------

    /* ...receives the message and the message digest... */
    unsigned char* digest_2;
    unsigned int digestlen_2;
    HMAC_CTX* ctx_2;

    /* Buffer allocation for the digest */
    digest_2 = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));

    /* Context allocation */
    ctx_2 = HMAC_CTX_new();

    /* Hashing (initialization + single update + finalization */
    HMAC_Init_ex(ctx_2, key, key_len, EVP_sha256(), nullptr);
    HMAC_Update(ctx_2, (unsigned char*)msg, sizeof(msg));
    HMAC_Final  (ctx_2, digest_2, &digestlen_2);

    cout << "HMAC_2: " << digest << endl;

    /* Context deallocation */
    HMAC_CTX_free(ctx_2);

    if(CRYPTO_memcmp(digest_2, digest, EVP_MD_size(EVP_sha256())) == 0)
        cout << "HMAC uguali" << endl;
    else
        cerr << "HMAC diversi" << endl;

    return 0;
}