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

struct Generic {

    uint8_t iv[AES_BLOCK_SIZE];
    uint8_t* ciphertext;
    int ciphertext_size;
    uint8_t hmac[HMAC_DIGEST_SIZE];

    Generic() { ciphertext = nullptr; }

    Generic(unsigned char* session_key, unsigned char* hmac_key, uint8_t* plaintext, int plaintext_size) {

        // generate the ciphertext
        AesCbc encryptor(ENCRYPT, session_key);
        unsigned char* iv = nullptr;
        encryptor.run(plaintext, plaintext_size, ciphertext, ciphertext_size, iv);
        memcpy(this->iv, iv, AES_BLOCK_SIZE * sizeof(uint8_t));
        delete[] iv;

        // concatenate IV and ciphertext
        uint8_t* buffer = new uint8_t[(AES_BLOCK_SIZE + ciphertext_size) * sizeof(uint8_t)];
        memcpy(buffer, this->iv, AES_BLOCK_SIZE * sizeof(uint8_t));
        memcpy(buffer + (AES_BLOCK_SIZE * sizeof(uint8_t)), ciphertext, ciphertext_size * sizeof(uint8_t));

        // generate the HMAC
        Hmac hmac(hmac_key);
        unsigned char* digest = nullptr;
        unsigned int digest_size = 0;
        hmac.generate(buffer, (AES_BLOCK_SIZE + ciphertext_size) * sizeof(uint8_t), digest, digest_size);
        memcpy(this->hmac, digest, digest_size * sizeof(uint8_t));

        delete[] digest;
        delete[] buffer;
    }

    ~Generic() { delete[] ciphertext; }

    bool verifyHMAC(unsigned char* key) {

        // concatenate IV and ciphertext
        uint8_t* buffer = new uint8_t[(AES_BLOCK_SIZE + ciphertext_size) * sizeof(uint8_t)];
        memcpy(buffer, iv, AES_BLOCK_SIZE * sizeof(uint8_t));
        memcpy(buffer + (AES_BLOCK_SIZE * sizeof(uint8_t)), ciphertext, ciphertext_size * sizeof(uint8_t));

        // verify the HMAC
        Hmac hmac(key);
        bool res = hmac.verify(buffer, (AES_BLOCK_SIZE + ciphertext_size) * sizeof(uint8_t), this->hmac, HMAC_DIGEST_SIZE * sizeof(uint8_t));

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

        int buffer_size = (AES_BLOCK_SIZE + ciphertext_size + HMAC_DIGEST_SIZE) * sizeof(uint8_t);
        uint8_t* buffer = new uint8_t[buffer_size];

        size_t position = 0;
        memcpy(buffer, iv, AES_BLOCK_SIZE * sizeof(uint8_t));
        position += AES_BLOCK_SIZE * sizeof(uint8_t);

        memcpy(buffer + position, ciphertext, ciphertext_size * sizeof(uint8_t));
        position += ciphertext_size * sizeof(uint8_t);

        memcpy(buffer + position, hmac, HMAC_DIGEST_SIZE * sizeof(uint8_t));

        return buffer;
    }

    static Generic deserialize(uint8_t* buffer, int buffer_size) {

        Generic genericPacket;
        genericPacket.ciphertext_size = buffer_size - ((AES_BLOCK_SIZE + HMAC_DIGEST_SIZE) * sizeof(uint8_t));

        size_t position = 0;
        memcpy(genericPacket.iv, buffer, AES_BLOCK_SIZE * sizeof(uint8_t));
        position += AES_BLOCK_SIZE * sizeof(uint8_t);

        genericPacket.ciphertext = new uint8_t[genericPacket.ciphertext_size];
        memcpy(genericPacket.ciphertext, buffer + position, genericPacket.ciphertext_size * sizeof(uint8_t));
        position += genericPacket.ciphertext_size * sizeof(uint8_t);

        memcpy(genericPacket.hmac, buffer + position, HMAC_DIGEST_SIZE * sizeof(uint8_t));

        return genericPacket;
    }

    static int getSize(int plaintext_size) {

        // calculate the ciphertext size
        int ciphertext_size = plaintext_size + (AES_BLOCK_SIZE - (plaintext_size % AES_BLOCK_SIZE));

        int size = 0;

        size += AES_BLOCK_SIZE * sizeof(uint8_t);
        size += ciphertext_size * sizeof(uint8_t);
        size += HMAC_DIGEST_SIZE * sizeof(uint8_t);

        return size;
    }

    void print() const {

        cout << "------- GENERIC PACKET -------" << endl;
        cout << "IV: ";
        for (int i = 0; i < AES_BLOCK_SIZE; ++i)
            cout << hex << (int)iv[i];
        cout << dec << endl;
        cout << "CIPHERTEXT (first 10 bytes): ";
        for (int i = 0; i < 10; ++i)
            cout << hex << (int)ciphertext[i];
        cout << dec << endl;  
        cout << "HMAC: ";
        for (int i = 0; i < HMAC_DIGEST_SIZE; ++i)
            cout << hex << (int)hmac[i];
        cout << dec << endl;        
        cout << "------------------------------" << endl;
    }
};

// ------------------------------------------------------------------------------------

#endif // _GENERICPACKET_H
