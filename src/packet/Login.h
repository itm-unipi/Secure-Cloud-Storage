#ifndef _LOGINPACKETS_H
#define _LOGINPACKETS_H

#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>
#include <arpa/inet.h>

#include "../security/CertificateStore.h"
#include "../client/Client.h"
#include "../../resources/Config.h"

using namespace std;

// --------------------------------------- M1 ---------------------------------------

struct LoginM1 {

    uint8_t ephemeral_key[1024];    // 1024 is an upper bound, there is no fixed size for OpenSSL ephemeral key
    uint32_t ephemeral_key_size;
    char username[USERNAME_SIZE];

    LoginM1() {}

    LoginM1(uint8_t* ephemeral_key, int ephemeral_key_size, string username) {

        memset(this->ephemeral_key, 0, sizeof(this->ephemeral_key));
        memcpy(this->ephemeral_key, ephemeral_key, ephemeral_key_size);

        this->ephemeral_key_size = (unsigned int)ephemeral_key_size;

        memset(this->username, 0, sizeof(this->username));
        strcpy(this->username, username.c_str());
    }

    uint8_t* serialize() const {

        uint8_t* buffer = new uint8_t[LoginM1::getSize()];

        size_t position = 0;
        memcpy(buffer, ephemeral_key, 1024 * sizeof(uint8_t));
        position += 1024 * sizeof(uint8_t);

        uint32_t ephemeral_key_size_hton = htonl(ephemeral_key_size);
        memcpy(buffer + position, &ephemeral_key_size_hton, sizeof(uint32_t));
        position += sizeof(uint32_t);

        memcpy(buffer + position, username, USERNAME_SIZE * sizeof(char));

        return buffer;
    }

    static LoginM1 deserialize(uint8_t* buffer) {

        LoginM1 loginM1;

        size_t position = 0;
        memcpy(loginM1.ephemeral_key, buffer, 1024 * sizeof(uint8_t));
        position += 1024 * sizeof(uint8_t);

        uint32_t ephemeral_key_size_hton = 0;
        memcpy(&ephemeral_key_size_hton, buffer + position, sizeof(uint32_t));
        loginM1.ephemeral_key_size = ntohl(ephemeral_key_size_hton);
        position += sizeof(uint32_t);

        memcpy(loginM1.username, buffer + position, USERNAME_SIZE * sizeof(char));

        return loginM1;
    }

    static int getSize() {

        int size = 0;

        size += 1024 * sizeof(uint8_t);
        size += sizeof(uint32_t);
        size += USERNAME_SIZE * sizeof(char);

        return size;
    }

    void print() const {

        cout << "---------- LOGIN M1 ----------" << endl;
        cout << "EPHEMERAL KEY:" << endl;
        for (int i = 0; i < 1024; ++i)
            cout << hex << ephemeral_key[i];
        cout << dec << endl;
        cout << "EPHEMERAL KEY SIZE: " << ephemeral_key_size << endl;
        cout << "USERNAME: " << username << endl;
        cout << "------------------------------" << endl;
    }
};

// --------------------------------------- M2 ---------------------------------------

struct LoginM2 {

    uint8_t result;

    LoginM2() {}

    LoginM2(uint8_t result) {

        this->result = result;
    }

    uint8_t* serialize() const {

        uint8_t* buffer = new uint8_t[LoginM1::getSize()];

        memcpy(buffer, &result, sizeof(uint8_t));

        return buffer;
    }

    static LoginM2 deserialize(uint8_t* buffer) {

        LoginM2 loginM2;

        memcpy(&loginM2.result, buffer, sizeof(uint8_t));

        return loginM2;
    }

    static int getSize() {

        return sizeof(uint8_t);
    }

    void print() const {

        cout << "---------- LOGIN M2 ----------" << endl;
        string result = this->result ? "username found" : "username not found";
        cout << "RESULT: " << result << endl;
        cout << "------------------------------" << endl;
    }
};

// --------------------------------------- M3 ---------------------------------------

struct LoginM3 {

    uint8_t ephemeral_key[1024];
    uint32_t ephemeral_key_size;
    uint8_t iv[AES_BLOCK_SIZE];
    uint8_t encrypted_signature[144];
    uint8_t serialized_certificate[MAX_SERIALIZED_CERTIFICATE_SIZE];
    uint32_t serialized_certificate_size;

    LoginM3() {}

    LoginM3(uint8_t* ephemeral_key, uint32_t ephemeral_key_size, uint8_t* iv, uint8_t* encrypted_signature, uint8_t* serialized_certificate, int serialized_certificate_size) {
        
        memset(this->ephemeral_key, 0, sizeof(this->ephemeral_key));
        memcpy(this->ephemeral_key, ephemeral_key, ephemeral_key_size);

        memcpy(this->iv, iv, AES_BLOCK_SIZE * sizeof(uint8_t));

        this->ephemeral_key_size = (unsigned int)ephemeral_key_size;

        memcpy(this->encrypted_signature, encrypted_signature, 144 * sizeof(uint8_t));

        memcpy(this->serialized_certificate, serialized_certificate, serialized_certificate_size);
        memset(this->serialized_certificate + serialized_certificate_size, 0, MAX_SERIALIZED_CERTIFICATE_SIZE - serialized_certificate_size);

        this->serialized_certificate_size = (unsigned int)serialized_certificate_size;
    }

    uint8_t* serialize() const {

        uint8_t* buffer = new uint8_t[LoginM3::getSize()];

        size_t position = 0;
        memcpy(buffer, ephemeral_key, 1024 * sizeof(uint8_t));
        position += 1024 * sizeof(uint8_t);

        uint32_t ephemeral_key_size_hton = htonl(ephemeral_key_size);
        memcpy(buffer + position, &ephemeral_key_size_hton, sizeof(uint32_t));
        position += sizeof(uint32_t);

        memcpy(buffer + position, iv, AES_BLOCK_SIZE * sizeof(uint8_t));
        position += AES_BLOCK_SIZE * sizeof(uint8_t);

        memcpy(buffer + position, encrypted_signature, 144 * sizeof(uint8_t));
        position += 144 * sizeof(uint8_t);

        memcpy(buffer + position, serialized_certificate, MAX_SERIALIZED_CERTIFICATE_SIZE);
        position += MAX_SERIALIZED_CERTIFICATE_SIZE;

        uint32_t serialized_certificate_size_hton = htonl(serialized_certificate_size);
        memcpy(buffer + position, &serialized_certificate_size_hton, sizeof(uint32_t));

        return buffer;
    }

    static LoginM3 deserialize(uint8_t* buffer) {

        LoginM3 loginM3;

        size_t position = 0;
        memcpy(loginM3.ephemeral_key, buffer, 1024 * sizeof(uint8_t));
        position += 1024 * sizeof(uint8_t);

        uint32_t ephemeral_key_size_hton = 0;
        memcpy(&ephemeral_key_size_hton, buffer + position, sizeof(uint32_t));
        loginM3.ephemeral_key_size = ntohl(ephemeral_key_size_hton);
        position += sizeof(uint32_t);

        memcpy(loginM3.iv, buffer + position, AES_BLOCK_SIZE * sizeof(uint8_t));
        position += AES_BLOCK_SIZE * sizeof(uint8_t);

        memcpy(loginM3.encrypted_signature, buffer + position, 144 * sizeof(uint8_t));
        position += 144 * sizeof(uint8_t);

        memcpy(loginM3.serialized_certificate, buffer + position, MAX_SERIALIZED_CERTIFICATE_SIZE);
        position += MAX_SERIALIZED_CERTIFICATE_SIZE;

        uint32_t serialized_certificate_size_hton = 0;
        memcpy(&serialized_certificate_size_hton, buffer + position, sizeof(uint32_t));
        loginM3.serialized_certificate_size = ntohl(serialized_certificate_size_hton);

        return loginM3;
    }

    static int getSize() {

        int size = 0;

        size += 1024 * sizeof(uint8_t);
        size += sizeof(uint32_t);
        size += AES_BLOCK_SIZE * sizeof(uint8_t);
        size += 144 * sizeof(uint8_t);
        size += MAX_SERIALIZED_CERTIFICATE_SIZE * sizeof(uint8_t);
        size += sizeof(uint32_t);

        return size;
    }

    void print() const {

        cout << "---------- LOGIN M3 ----------" << endl;
        cout << "EPHEMERAL KEY:" << endl;
        for (int i = 0; i < 1024; ++i)
            cout << hex << ephemeral_key[i];
        cout << dec << endl;
        cout << "EPHEMERAL KEY SIZE: " << ephemeral_key_size << endl;
        cout << "IV:" << endl;
        for (int i = 0; i < AES_BLOCK_SIZE; ++i)
            cout << hex << iv[i];
        cout << dec << endl;
        cout << "ENCRYPTED SIGNATURE:" << endl;
        for (int i = 0; i < 144; ++i)
            cout << hex << encrypted_signature[i];
        cout << dec << endl;
        cout << "SERIALIZED CERTIFICATE:" << endl;
        for (int i = 0; i < (int)serialized_certificate_size; ++i)
            cout << hex << serialized_certificate[i];
        cout << dec << endl;
        cout << "SERIALIZED CERTIFICATE SIZE: " << serialized_certificate_size << endl;
        cout << "------------------------------" << endl;
    }
};

// --------------------------------------- M4 ---------------------------------------

struct LoginM4 {

    uint8_t iv[AES_BLOCK_SIZE];
    uint8_t encrypted_signature[144];           // 128 bytes (long term key size) + 16 bytes (padding block) 

    LoginM4() {}

    LoginM4(uint8_t* iv, uint8_t* encrypted_signature) {
        
        memcpy(this->iv, iv, AES_BLOCK_SIZE * sizeof(uint8_t));
        memcpy(this->encrypted_signature, encrypted_signature, 144 * sizeof(uint8_t));
    }

    uint8_t* serialize() const {

        uint8_t* buffer = new uint8_t[LoginM4::getSize()];

        size_t position = 0;
        memcpy(buffer, iv, AES_BLOCK_SIZE * sizeof(uint8_t));
        position += AES_BLOCK_SIZE * sizeof(uint8_t);

        memcpy(buffer + position, encrypted_signature, 144 * sizeof(uint8_t));

        return buffer;
    }

    static LoginM4 deserialize(uint8_t* buffer) {

        LoginM4 loginM4;

        size_t position = 0;
        memcpy(loginM4.iv, buffer, AES_BLOCK_SIZE * sizeof(uint8_t));
        position += AES_BLOCK_SIZE * sizeof(uint8_t);

        memcpy(loginM4.encrypted_signature, buffer + position, 144 * sizeof(uint8_t));
        position += 144 * sizeof(uint8_t);

        return loginM4;
    }

    static int getSize() {

        int size = 0;

        size += AES_BLOCK_SIZE * sizeof(uint8_t);
        size += 144 * sizeof(uint8_t);

        return size;
    }

    void print() const {

        cout << "---------- LOGIN M4 ----------" << endl;
        cout << "IV:" << endl;
        for (int i = 0; i < AES_BLOCK_SIZE; ++i)
            cout << hex << iv[i];
        cout << dec << endl;
        cout << "ENCRYPTED SIGNATURE:" << endl;
        for (int i = 0; i < 144; ++i)
            cout << hex << encrypted_signature[i];
        cout << dec << endl;
        cout << "------------------------------" << endl;
    }
};

// ----------------------------------------------------------------------------------

#endif // _LOGINPACKETS_H
