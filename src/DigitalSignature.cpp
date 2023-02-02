#include <iostream>
#include <openssl/pem.h>

#include "DigitalSignature.h"

using namespace std;

void DigitalSignature::generate(unsigned char* input_buffer, 
                                long int input_buffer_size, 
                                unsigned char*& signature, 
                                unsigned int& signature_size, 
                                EVP_PKEY* private_key) {

    signature = new unsigned char[EVP_PKEY_size(private_key)];
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    
    EVP_SignInit(ctx, EVP_sha256());
    EVP_SignUpdate(ctx, input_buffer, input_buffer_size);
    EVP_SignFinal(ctx, signature, &signature_size, private_key);

    EVP_MD_CTX_free(ctx);
}

bool DigitalSignature::verify(unsigned char* input_buffer, 
                            long int input_buffer_size, 
                            unsigned char* signature, 
                            unsigned int signature_size, 
                            EVP_PKEY* public_key) {
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    EVP_VerifyInit(ctx, EVP_sha256());
    EVP_VerifyUpdate(ctx, input_buffer, input_buffer_size);
    int res = EVP_VerifyFinal(ctx, signature, signature_size, public_key);

    EVP_MD_CTX_free(ctx);

    if (res != 1) {
        if (res != 0)
            cerr << "[-] (DigitalSignature) Failed to verify signature" << endl;
        return false;
    }

    return true;    
}