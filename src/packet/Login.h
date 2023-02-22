#ifndef _LOGINPACKETS_H
#define _LOGINPACKETS_H

#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>
#include <arpa/inet.h>
using namespace std;

// --------------------------------------- M1 ---------------------------------------

struct LoginM1 {

    uint8_t ephemeral_key[1024];
    uint32_t ephemeral_key_size;
    char username[30];

    LoginM1() {}

    LoginM1(uint8_t* ephemeral_key, int ephemeral_key_size, string username) {

        memset(this->ephemeral_key, 0, sizeof(this->ephemeral_key));
        memcpy(this->ephemeral_key, ephemeral_key, ephemeral_key_size);

        this->ephemeral_key_size = htonl((unsigned int)ephemeral_key_size);

        memset(this->username, 0, sizeof(this->username));
        strcpy(this->username, username.c_str());
    }

    uint8_t* serialize() const {

        uint8_t* buffer = new uint8_t[LoginM1::getSize()];

        size_t position = 0;
        memcpy(buffer, ephemeral_key, 1024 * sizeof(uint8_t));
        position += 1024 * sizeof(uint8_t);

        memcpy(buffer + position, &ephemeral_key_size, sizeof(uint32_t));
        position += sizeof(uint32_t);

        memcpy(buffer + position, username, 30 * sizeof(char));

        return buffer;
    }

    static LoginM1 deserialize(uint8_t* buffer) {

        LoginM1 loginM1;

        size_t position = 0;
        memcpy(loginM1.ephemeral_key, buffer, 1024 * sizeof(uint8_t));
        position += 1024 * sizeof(uint8_t);

        memcpy(&loginM1.ephemeral_key_size, buffer + position, sizeof(uint32_t));
        position += sizeof(uint32_t);

        memcpy(loginM1.username, buffer + position, 30 * sizeof(char));

        return loginM1;
    }

    static int getSize() {

        int size = 0;

        size += 1024 * sizeof(uint8_t);
        size += sizeof(uint32_t);
        size += 30 * sizeof(char);

        return size;
    }

    void print() const {

        cout << "---------- LOGIN M1 ----------" << endl;
        cout << "EPHEMERAL KEY:\n" << (char*)ephemeral_key << endl;
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



// --------------------------------------- M4 ---------------------------------------



// ----------------------------------------------------------------------------------



#endif // _LOGINPACKETS_H
