#include <openssl/evp.h>

#include "Sha512.h"

void Sha512::generate(unsigned char* input_buffer, 
                    size_t input_buffer_size, 
                    unsigned char*& digest, 
                    unsigned int& digest_size) {
    
    digest = new unsigned char[EVP_MD_size(EVP_sha512())];
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    EVP_DigestInit(ctx, EVP_sha512());
    EVP_DigestUpdate(ctx, input_buffer, input_buffer_size);
    EVP_DigestFinal(ctx, digest, &digest_size);

    EVP_MD_CTX_free(ctx);
}

bool Sha512::verify(unsigned char* input_buffer, 
                    size_t input_buffer_size, 
                    unsigned char* input_digest, 
                    unsigned int input_digest_size) {

    unsigned char* generated_digest = nullptr;
    unsigned int generated_digest_size = 0;

    Sha512::generate(input_buffer, input_buffer_size, generated_digest, generated_digest_size);
    bool res = CRYPTO_memcmp(input_digest, generated_digest, EVP_MD_size(EVP_sha256())) == 0;

    delete[] generated_digest;
    return res;
}
