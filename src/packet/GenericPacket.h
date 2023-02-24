#ifndef _GENERICPACKET_H
#define _GENERICPACKET_H

#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>
#include <openssl/rand.h>

#include "../security/AesCbc.h"
#include "../security/Hmac.h"

using namespace std;

// ---------------------------------- GENERIC PACKET ----------------------------------

struct GenericPacket {

    uint8_t iv[16];
    uint8_t* ciphertext;
    int ciphertext_size;
    uint8_t hmac[32];

    GenericPacket() {}

    GenericPacket(unsigned char* session_key, unsigned char* hmac_key, uint8_t* plaintext, int plaintext_size/*, int expected_plaintext_size = -1*/) {

        /*/ check if is needed to generate random bytes in the plaintext
        if (expected_plaintext_size != -1 && expected_plaintext_size > plaintext_size) {
            // create a new plaintext buffer with the wanted size
            uint8_t* old_plaintext = plaintext;
            plaintext = new uint8_t[expected_plaintext_size];

            // concatenate old plaintext with the random bytes
            memcpy(plaintext, old_plaintext, plaintext_size);
            RAND_bytes(plaintext + plaintext_size, expected_plaintext_size - plaintext_size);

            // remove from memory the old plaintext
            #pragma optimize("", off)
            memset(old_plaintext, 0, plaintext_size);
            #pragma optimize("", on)
            delete[] old_plaintext;

            plaintext_size = expected_plaintext_size;
        }*/

        // generate the ciphertext
        AesCbc encryptor(ENCRYPT, session_key);
        unsigned char* iv = nullptr;
        encryptor.run(plaintext, plaintext_size, ciphertext, ciphertext_size, iv);
        memcpy(this->iv, iv, 16 * sizeof(uint8_t));
        delete[] iv;

        // concatenate IV and ciphertext
        uint8_t* buffer = new uint8_t[16 + ciphertext_size];
        memcpy(buffer, iv, 16);
        memcpy(buffer + 16, ciphertext, ciphertext_size);
        
        // generate the HMAC
        Hmac hmac(hmac_key);
        unsigned char* digest = nullptr;
        unsigned int digest_size = 0;
        hmac.generate(buffer, 16 + ciphertext_size, digest, digest_size);
        memcpy(this->hmac, digest, digest_size * sizeof(uint8_t));

        delete[] digest;
        delete[] buffer;
    }

    bool verifyHMAC(unsigned char* key) {

        // concatenate IV and ciphertext
        uint8_t* buffer = new uint8_t[16 + ciphertext_size];
        memcpy(buffer, iv, 16);
        memcpy(buffer + 16, ciphertext, ciphertext_size);

        // verify the HMAC
        Hmac hmac(key);
        bool res = hmac.verify(buffer, 16 + ciphertext_size, this->hmac, 32 * sizeof(uint8_t));

        delete[] buffer;
        return res;
    }

    uint8_t* serialize() const {

        uint8_t* buffer = new uint8_t[GenericPacket::getSize(ciphertext_size)];

        size_t position = 0;
        memcpy(buffer, iv, 16 * sizeof(uint8_t));
        position += 16 * sizeof(uint8_t);

        memcpy(buffer + position, ciphertext, ciphertext_size * sizeof(uint8_t));
        position += ciphertext_size * sizeof(uint8_t);

        memcpy(buffer + position, hmac, 32 * sizeof(uint8_t));

        return buffer;
    }

    static GenericPacket deserialize(uint8_t* buffer, int buffer_size) {

        GenericPacket genericPacket;
        genericPacket.ciphertext_size = buffer_size - ((16 + 32) * sizeof(uint8_t));

        size_t position = 0;
        memcpy(genericPacket.iv, buffer, 16 * sizeof(uint8_t));
        position += 16 * sizeof(uint8_t);

        memcpy(genericPacket.ciphertext, buffer + position, genericPacket.ciphertext_size * sizeof(uint8_t));
        position += genericPacket.ciphertext_size * sizeof(uint8_t);

        memcpy(genericPacket.hmac, buffer + position, 32 * sizeof(uint8_t));

        return genericPacket;
    }

    static int getSize(int ciphertext_size) {

        int size = 0;

        size += 16 * sizeof(uint8_t);
        size += ciphertext_size * sizeof(uint8_t);
        size += 32 * sizeof(uint8_t);

        return size;
    }

    void print() const {

        cout << "------- GENERIC PACKET -------" << endl;
        cout << "IV: ";
        for (int i = 0; i < 16; ++i)
            cout << iv[i];
        cout << endl;
        cout << "CIPHERTEXT (first 10 bytes): ";
        for (int i = 0; i < 10; ++i)
            cout << ciphertext[i];
        cout << endl;  
        cout << "HMAC: ";
        for (int i = 0; i < 16; ++i)
            cout << hmac[i];
        cout << endl;        
        cout << "------------------------------" << endl;
    }
};

// ------------------------------------------------------------------------------------

#endif // _GENERICPACKET_H
