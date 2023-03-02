#ifndef _RENAME_H
#define _RENAME_H

#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>

#include "./CommandCodes.h"

using namespace std;

#define FILE_NAME_SIZE 30 // TODO valutare se metterlo da un altra parte

// ----------------------------------- RENAME M1 ------------------------------------

struct RenameM1 {

    uint8_t command_code;
    uint32_t counter;
    uint8_t file_name[FILE_NAME_SIZE];
    uint8_t new_file_name[FILE_NAME_SIZE];

    RenameM1() {}

    RenameM1(uint32_t counter, string file_name, string new_file_name) {
        this->command_code = RENAME_REQ;
        this->counter = counter;
        memcpy(&this->file_name, file_name.c_str(), FILE_NAME_SIZE);
        memcpy(&this->new_file_name, new_file_name.c_str(), FILE_NAME_SIZE);
    }

    uint8_t* serialize() const {

        uint8_t* buffer = new uint8_t[RenameM1::getSize()];

        size_t position = 0;
        memcpy(buffer, &command_code, sizeof(uint8_t));
        position += sizeof(uint8_t);

        memcpy(buffer + position, &counter, sizeof(uint32_t));
        position += sizeof(uint32_t);

        memcpy(buffer + position, &file_name, FILE_NAME_SIZE * sizeof(uint8_t));
        position += FILE_NAME_SIZE * sizeof(uint8_t);

        memcpy(buffer + position, &new_file_name, FILE_NAME_SIZE * sizeof(uint8_t));
    
        return buffer;
    }

    static RenameM1 deserialize(uint8_t* buffer) {

        RenameM1 renameM1;

        size_t position = 0;
        memcpy(&renameM1.command_code, buffer, sizeof(uint8_t));
        position += sizeof(uint8_t);

        memcpy(&renameM1.counter, buffer + position, sizeof(uint32_t));
        position += sizeof(uint32_t);

        memcpy(&renameM1.file_name, buffer + position, FILE_NAME_SIZE * sizeof(uint8_t));
        position += FILE_NAME_SIZE * sizeof(uint8_t);

        memcpy(&renameM1.new_file_name, buffer + position, FILE_NAME_SIZE * sizeof(uint8_t));

        return renameM1;
    }

    static int getSize() {
        int size = 0;

        size += sizeof(uint8_t);
        size += sizeof(uint32_t);
        size += FILE_NAME_SIZE * sizeof(uint8_t);
        size += FILE_NAME_SIZE * sizeof(uint8_t);

        return size;
     }

    void print() const {

        cout << "--------- RENAME M1 ----------" << endl;
        cout << "COMMAND CODE: " << printCommandCodeDescription(command_code) << endl;
        cout << "COUNTER: " << counter << endl;
        cout << "FILE NAME: " << (char*)file_name << endl;
        cout << "NEW FILE NAME: " << (char*)new_file_name << endl;

    }
};

// ----------------------------------------------------------------------------------

#endif // _RENAME_H
