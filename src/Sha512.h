#ifndef _SHA512_H
#define _SHA512_H

#include <cstdlib>

class Sha512 {

public:
    Sha512() {}
    Sha512(const Sha512&) = delete;
    ~Sha512() {}

    static void generate(unsigned char* input_buffer, size_t input_buffer_size, unsigned char*& digest, unsigned int& digest_size);
    static bool verify(unsigned char* input_buffer, size_t input_buffer_size, unsigned char* input_digest, unsigned int input_digest_size);
};

#endif  // _SHA512_H
