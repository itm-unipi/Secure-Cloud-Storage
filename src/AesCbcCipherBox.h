#ifndef _AESCBCCIPHERBOX_H
#define _AESCBCCIPHERBOX_H

#include <cstdint>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#define ENCRYPT 0
#define DECRYPT 1
#define BLOCK_SIZE 128

class AesCbcCipherBox {

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

    int initialize();
    int update();
    int finalize();

public:
    AesCbcCipherBox(uint8_t type, unsigned char* key);
    AesCbcCipherBox(const AesCbcCipherBox&) = delete;
    ~AesCbcCipherBox();
    void run(unsigned char* input_buffer, long int input_buffer_size, unsigned char*& output_buffer, int& output_buffer_size, unsigned char*& iv);
    int getIvSize() { return m_iv_size; }
};

#endif  // _AESCBCCIPHERBOX_H