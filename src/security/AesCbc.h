#ifndef _AESCBC_H
#define _AESCBC_H

#include <cstdint>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#define ENCRYPT 0
#define DECRYPT 1
#define AES_KEY_SIZE 32
#define AES_BLOCK_SIZE 16

class AesCbc {

    uint8_t m_type;
    unsigned char* m_key;
    unsigned char* m_plaintext;
    long int m_plaintext_size;
    unsigned char* m_iv;
    int m_iv_size;
    unsigned char* m_ciphertext;
    int m_ciphertext_size;
    EVP_CIPHER_CTX* m_ctx;
    int m_processed_bytes;

    // encrypt methods
    int initializeEncrypt();
    int updateEncrypt();
    int finalizeEncrypt();

    // decrypt methods
    int initializeDecrypt();
    int updateDecrypt();
    int finalizeDecrypt();

public:
    AesCbc(uint8_t type, unsigned char* key);
    AesCbc(const AesCbc&) = delete;
    ~AesCbc();
    void run(unsigned char* input_buffer, long int input_buffer_size, unsigned char*& output_buffer, int& output_buffer_size, unsigned char*& iv);

    static int getIvSize() { return EVP_CIPHER_iv_length(EVP_aes_256_cbc()); }
};

#endif  // _AESCBC_H
