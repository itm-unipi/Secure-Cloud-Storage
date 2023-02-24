#ifndef _LOGOUTPACKETS_H
#define _LOGOUTPACKETS_H

#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>
#include <openssl/rand.h>

#include "./CommandCodes.h"

using namespace std;

// --------------------------------------- M1 ---------------------------------------

struct LogoutM1 {

    uint8_t command_code;
    uint32_t counter;

    LogoutM1() {}

    LogoutM1(uint32_t counter) {
        this->command_code = LOGOUT_REQ;
        this->counter = counter;
    }

    uint8_t* serialize() const {
        
        uint8_t* buffer = new uint8_t[COMMAND_FIELD_PACKET_SIZE];

        size_t position = 0;
        memcpy(buffer, &command_code, sizeof(uint8_t));
        position += sizeof(uint8_t);

        memcpy(buffer + position, &counter, sizeof(uint32_t));
        position += sizeof(uint32_t);

        // add random bytes
        RAND_bytes(buffer + position, COMMAND_FIELD_PACKET_SIZE - position);
    
        return buffer;
    }

    static LogoutM1 deserialize(uint8_t* buffer) {

        LogoutM1 logoutM1;

        size_t position = 0;
        memcpy(&logoutM1.command_code, buffer, sizeof(uint8_t));
        position += sizeof(uint8_t);

        memcpy(&logoutM1.counter, buffer + position, sizeof(uint32_t));

        return logoutM1;
    }

    void print() const {

        cout << "--------- LOGOUT M1 ----------" << endl;
        cout << "COMMAND CODE: " << printCommandCodeDescription(command_code) << endl;
        cout << "COUNTER: " << counter << endl;
        cout << "------------------------------" << endl;
    }
};

// ----------------------------------------------------------------------------------

#endif // _LOGOUTPACKETS_H
