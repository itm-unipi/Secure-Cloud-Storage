#ifndef _RESULT_H
#define _RESULT_H

#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>
#include <openssl/rand.h>

#include "./CommandCodes.h"

using namespace std;

// ------------------------------------- RESULT -------------------------------------

struct Result {

    uint8_t command_code;
    uint8_t error_code;
    uint32_t counter;

    Result() {}

    Result(uint32_t counter, bool success, uint8_t error_code = 0) {
        if (success) {
            this->command_code = REQ_SUCCESS;
        } else {
            this->command_code = REQ_FAILED;
            this->error_code = error_code;
        }

        this->counter = counter;
    }

    uint8_t* serialize() const {
        
        uint8_t* buffer = new uint8_t[Result::getSize()];

        size_t position = 0;
        memcpy(buffer, &command_code, sizeof(uint8_t));
        position += sizeof(uint8_t);

        if (command_code == REQ_FAILED)
            memcpy(buffer + position, &error_code, sizeof(uint8_t));
        else
            RAND_bytes(buffer + position, sizeof(uint8_t));
        position += sizeof(uint8_t);

        memcpy(buffer + position, &counter, sizeof(uint32_t));
    
        return buffer;
    }

    static Result deserialize(uint8_t* buffer) {

        Result result;

        size_t position = 0;
        memcpy(&result.command_code, buffer, sizeof(uint8_t));
        position += sizeof(uint8_t);

        if (result.command_code == REQ_FAILED)
            memcpy(&result.error_code, buffer + position, sizeof(uint8_t));
        position += sizeof(uint8_t);

        memcpy(&result.counter, buffer + position, sizeof(uint32_t));

        return result;
    }

    static int getSize() {

        int size = 0;

        size += 2 * sizeof(uint8_t);
        size += sizeof(uint32_t);

        return size;
    }

    void print() const {

        cout << "--------- RESULT ----------" << endl;
        cout << "COMMAND CODE: " << printCommandCodeDescription(command_code) << endl;
        if (command_code == REQ_FAILED)
            cout << "ERROR CODE: " << printErrorCodeDescription(error_code) << endl;
        cout << "COUNTER: " << counter << endl;
        cout << "------------------------------" << endl;
    }
};

// ----------------------------------------------------------------------------------

#endif // _RESULT_H
