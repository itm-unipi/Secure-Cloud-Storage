#ifndef _HMAC_H
#define _HMAC_H

#define HMAC_DIGEST_SIZE 32

class Hmac {

    unsigned char* m_key;

public:
    Hmac(unsigned char* key);
    Hmac(const Hmac&) = delete;
    ~Hmac();

    void generate(unsigned char* input_buffer, size_t input_buffer_size, unsigned char*& digest, unsigned int& digest_size);
    bool verify(unsigned char* input_buffer, size_t input_buffer_size, unsigned char* input_digest, unsigned int input_digest_size);
};

#endif  // _HMAC_H
