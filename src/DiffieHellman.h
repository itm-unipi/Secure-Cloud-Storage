#ifndef _DIFFIEHELLMAN_H
#define _DIFFIEHELLMAN_H

#include <openssl/evp.h>

class DiffieHellman {

    EVP_PKEY *m_dh_parameters;

public:
    DiffieHellman();
    DiffieHellman(const DiffieHellman&) = delete;
    ~DiffieHellman();

    EVP_PKEY* generateEphemeralKey();
    int generateSharedSecret(EVP_PKEY* ephemeral_key_1, EVP_PKEY* ephemeral_key_2, unsigned char*& shared_secret, size_t& shared_secret_size);
};

#endif // _DIFFIEHELLMAN_H
