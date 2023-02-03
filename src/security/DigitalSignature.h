#ifndef _DIGITALSIGNATURE_H
#define _DIGITALSIGNATURE_H

#include <openssl/evp.h>

#define SIGNATURE_SIZE 512

class DigitalSignature {

public:
    DigitalSignature() {}
    DigitalSignature(const DigitalSignature&) = delete;
    ~DigitalSignature() {}

    static void generate(unsigned char* input_buffer, long int input_buffer_size, unsigned char*& signature, unsigned int& signature_size, EVP_PKEY* private_key);
    static bool verify(unsigned char* input_buffer, long int input_buffer_size, unsigned char* signature, unsigned int signature_size, EVP_PKEY* public_key);
};

#endif  // _DIGITALSIGNATURE_H
