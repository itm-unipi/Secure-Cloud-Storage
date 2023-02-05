#include <iostream>
#include <cstring>
#include <openssl/evp.h>

#include "../src/security/DiffieHellman.h"
#include "../src/security/Sha512.h"

using namespace std;

int main() {

    // ------------------ SHARED SECRET GENERATIONS ------------------

    DiffieHellman dh1;
    DiffieHellman dh2;

    EVP_PKEY* ephemeral_key_1 = dh1.generateEphemeralKey();
    EVP_PKEY* ephemeral_key_2 = dh2.generateEphemeralKey();

    unsigned char *shared_secret_1, *shared_secret_2;
    size_t shared_secret_size_1, shared_secret_size_2;

    dh1.generateSharedSecret(ephemeral_key_1, ephemeral_key_2, shared_secret_1, shared_secret_size_1);
    dh2.generateSharedSecret(ephemeral_key_2, ephemeral_key_1, shared_secret_2, shared_secret_size_2);

    cout << "\nSHARED SECRET 1:" << endl;
    BIO_dump_fp(stdout, (const char *)shared_secret_1, shared_secret_size_1);
    cout << "\nSHARED SECRET size:" << shared_secret_size_1 << endl;
    cout << "\nSHARED SECRET 2:" << endl;
    BIO_dump_fp(stdout, (const char *)shared_secret_2, shared_secret_size_2);

    // ------------- SESSION KEY AND HMAC KEY GENERATION -------------

    unsigned char* digest;
    unsigned int digest_size;
    Sha512::generate(shared_secret_1, shared_secret_size_1, digest, digest_size);

    int key_size = (int)(digest_size / 2);
    unsigned char* session_key = new unsigned char[key_size];
    unsigned char* hmac_key = new unsigned char[key_size];

    memcpy(session_key, digest, key_size);
    memcpy(hmac_key, digest + key_size, key_size);

    cout << "\nSESSION KEY:" << endl;
    BIO_dump_fp(stdout, (const char *)session_key, key_size);
    cout << "\nHMAC KEY:" << endl;
    BIO_dump_fp(stdout, (const char *)hmac_key, key_size);

    // --------------------- TEST SERIALIZATION ----------------------

    uint8_t* serialized_ek = nullptr;
    int serialized_ek_size;
    DiffieHellman::serializeKey(ephemeral_key_1, serialized_ek, serialized_ek_size);
    EVP_PKEY* deserialized_ek = DiffieHellman::deserializeKey(serialized_ek, serialized_ek_size);

    int result = EVP_PKEY_cmp(ephemeral_key_1, deserialized_ek);
    if (result == 1) {
        std::cout << "Le chiavi sono uguali" << std::endl;
    } else {
        std::cout << "Le chiavi sono diverse" << std::endl;
    }

    // ---------------------------------------------------------------

    EVP_PKEY_free(ephemeral_key_1);
    EVP_PKEY_free(ephemeral_key_2);
    EVP_PKEY_free(deserialized_ek);
    delete[] shared_secret_1;
    delete[] shared_secret_2;
    delete[] digest;
    delete[] session_key;
    delete[] hmac_key;
    delete[] serialized_ek;

    return 0;
}