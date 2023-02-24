#ifndef _GENERICPACKET_H
#define _GENERICPACKET_H

#define MAX_COUNTER_VALUE 0xffffffff

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

    GenericPacket() { ciphertext = nullptr; }

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
        uint8_t* buffer = new uint8_t[(16 + ciphertext_size) * sizeof(uint8_t)];
        memcpy(buffer, this->iv, 16 * sizeof(uint8_t));
        memcpy(buffer + (16 * sizeof(uint8_t)), ciphertext, ciphertext_size * sizeof(uint8_t));
        
        cout << "[test] HMAC key in generate = " << hmac_key << endl;

        cout << "[test] Buffer in generate = " << buffer << endl;

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

        cout << "[test] HMAC key in verify = " << key << endl;

        // concatenate IV and ciphertext
        uint8_t* buffer = new uint8_t[(16 + ciphertext_size) * sizeof(uint8_t)];
        memcpy(buffer, iv, 16 * sizeof(uint8_t));
        memcpy(buffer + (16 * sizeof(uint8_t)), ciphertext, ciphertext_size * sizeof(uint8_t));

        cout << "[test] Buffer in verify = " << buffer << endl;

        // verify the HMAC
        Hmac hmac(key);
        bool res = hmac.verify(buffer, (16 + ciphertext_size) * sizeof(uint8_t), this->hmac, 32 * sizeof(uint8_t));

        delete[] buffer;
        return res;
    }

    uint8_t decryptCiphertext(unsigned char* key, unsigned char*& plaintext, int& plaintext_size) {

        // decrypt the ciphertext
        AesCbc decryptor(DECRYPT, key);
        unsigned char* iv = this->iv;
        decryptor.run(ciphertext, ciphertext_size, plaintext, plaintext_size, iv);

        // return the packet type
        uint8_t type;
        memcpy(&type, plaintext, sizeof(uint8_t));
        return type;
    }

    uint8_t* serialize() const {

        int buffer_size = (16 + ciphertext_size + 32) * sizeof(uint8_t);
        uint8_t* buffer = new uint8_t[buffer_size];

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

        genericPacket.ciphertext = new uint8_t[genericPacket.ciphertext_size];
        memcpy(genericPacket.ciphertext, buffer + position, genericPacket.ciphertext_size * sizeof(uint8_t));
        position += genericPacket.ciphertext_size * sizeof(uint8_t);

        memcpy(genericPacket.hmac, buffer + position, 32 * sizeof(uint8_t));

        return genericPacket;
    }

    static int getSize(int plaintext_size) {

        // calculate the ciphertext size
        int ciphertext_size = plaintext_size + (16 - (plaintext_size % 16));

        // cout << "[test] plaintext size = " << plaintext_size << " | ciphertext size = " << ciphertext_size << endl;

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
