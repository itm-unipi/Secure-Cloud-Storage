#ifndef _REMOVE_H
#define _REMOVE_H

#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>

#include "./CommandCodes.h"

using namespace std;

// ----------------------------------- REMOVE M1 ------------------------------------

struct RemoveM1 {

    uint8_t command_code;
    uint32_t counter;
    char file_name[FILE_NAME_SIZE];

    RemoveM1() {}

    RemoveM1(uint32_t counter, string file_name) {
        this->command_code = DELETE_REQ;
        this->counter = counter;
        strncpy(this->file_name, file_name.c_str(), FILE_NAME_SIZE);
    }

    uint8_t* serialize() const {

        uint8_t* buffer = new uint8_t[COMMAND_FIELD_PACKET_SIZE];

        size_t position = 0;
        memcpy(buffer, &command_code, sizeof(uint8_t));
        position += sizeof(uint8_t);

        memcpy(buffer + position, &counter, sizeof(uint32_t));
        position += sizeof(uint32_t);

        memcpy(buffer + position, &file_name, FILE_NAME_SIZE * sizeof(char));
        position += FILE_NAME_SIZE * sizeof(char);

        // add random bytes
        RAND_bytes(buffer + position, COMMAND_FIELD_PACKET_SIZE - position);
    
        return buffer;
    }

    static RemoveM1 deserialize(uint8_t* buffer) {

        RemoveM1 removeM1;

        size_t position = 0;
        memcpy(&removeM1.command_code, buffer, sizeof(uint8_t));
        position += sizeof(uint8_t);

        memcpy(&removeM1.counter, buffer + position, sizeof(uint32_t));
        position += sizeof(uint32_t);

        memcpy(&removeM1.file_name, buffer + position, FILE_NAME_SIZE * sizeof(char));
       
        return removeM1;
    }

    static int getSize() {
        
        int size = 0;

        size += sizeof(uint8_t);
        size += sizeof(uint32_t);
        size += FILE_NAME_SIZE * sizeof(char);

        return size;
    }

    void print() const {

        cout << "--------- REMOVE M1 ----------" << endl;
        cout << "COMMAND CODE: " << printCommandCodeDescription(command_code) << endl;
        cout << "COUNTER: " << counter << endl;
        cout << "FILE NAME: " << file_name << endl;
        cout << "------------------------------" << endl;
    }
};

// ----------------------------------------------------------------------------------

#endif // _REMOVE_H
