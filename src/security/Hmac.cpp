#include <cstring>
#include <openssl/hmac.h>

#include "Hmac.h"

Hmac::Hmac(unsigned char* key) {

    m_key = new unsigned char[HMAC_DIGEST_SIZE];
    memcpy(m_key, key, HMAC_DIGEST_SIZE);
}

Hmac::~Hmac() {

#pragma optimize("", off)
    memset(m_key, 0, HMAC_DIGEST_SIZE);
#pragma optimize("", on)
    delete[] m_key;
}

void Hmac::generate(unsigned char* input_buffer, 
                    size_t input_buffer_size, 
                    unsigned char*& digest, 
                    unsigned int& digest_size) {
    
    digest = new unsigned char[EVP_MD_size(EVP_sha256())];
    HMAC_CTX* ctx = HMAC_CTX_new();

    HMAC_Init_ex(ctx, m_key, HMAC_DIGEST_SIZE, EVP_sha256(), nullptr);
    HMAC_Update(ctx, input_buffer, input_buffer_size);
    HMAC_Final(ctx, digest, &digest_size);    

    HMAC_CTX_free(ctx);
}

bool Hmac::verify(unsigned char* input_buffer, 
                size_t input_buffer_size, 
                unsigned char* input_digest, 
                unsigned int input_digest_size) {

    unsigned char* generated_digest = nullptr;
    unsigned int generated_digest_size = 0;

    generate(input_buffer, input_buffer_size, generated_digest, generated_digest_size);
    bool res = CRYPTO_memcmp(input_digest, generated_digest, EVP_MD_size(EVP_sha256())) == 0;

    delete[] generated_digest;
    return res;
}
