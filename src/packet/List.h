#ifndef _DELETE_H
#define _DELETE_H

#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>
#include <openssl/rand.h>

#include "./CommandCodes.h"

#define FILE_NAME_SIZE 30 //TODO valutare se metterlo da un altra parte

using namespace std;

// ------------------------------------ LIST M1 -------------------------------------

struct ListM1 {

    uint8_t command_code;
    uint32_t counter;


    ListM1() {}

    ListM1(uint32_t counter) {
        this->command_code = FILE_LIST_REQ;
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

    static ListM1 deserialize(uint8_t* buffer) {

        ListM1 listM1;

        size_t position = 0;
        memcpy(&listM1.command_code, buffer, sizeof(uint8_t));
        position += sizeof(uint8_t);

        memcpy(&listM1.counter, buffer + position, sizeof(uint32_t));

        return listM1;
    }

    void print() const {

        cout << "--------- LIST M1 ----------" << endl;
        cout << "COMMAND CODE: " << printCommandCodeDescription(command_code) << endl;
        cout << "COUNTER: " << counter << endl;
        cout << "------------------------------" << endl;
    }
};

// ------------------------------------ LIST M2 -------------------------------------

struct ListM2 {

    uint8_t command_code;
    uint32_t counter;
    uint32_t file_list_size;

    ListM2() {}

    ListM2(uint32_t counter, uint32_t file_list_size) {

        this->command_code = FILE_LIST_SIZE;
        this->counter = counter;
        this->file_list_size = file_list_size;
    }

    uint8_t* serialize() const { 

        uint8_t* buffer = new uint8_t[ListM2::getSize()];

        size_t position = 0;
        memcpy(buffer, &command_code, sizeof(uint8_t));
        position += sizeof(uint8_t);

        memcpy(buffer + position, &counter, sizeof(uint32_t));
        position += sizeof(uint32_t);

        memcpy(buffer + position, &file_list_size, sizeof(uint32_t));
    
        return buffer;

    }

    static ListM2 deserialize(uint8_t* buffer) {

        ListM2 listM2;

        size_t position = 0;
        memcpy(&listM2.command_code, buffer, sizeof(uint8_t));
        position += sizeof(uint8_t);

        memcpy(&listM2.counter, buffer + position, sizeof(uint32_t));
        position += sizeof(uint32_t);

        memcpy(&listM2.file_list_size, buffer + position, sizeof(uint32_t));

        return listM2;
    }

    static int getSize() {
        
        int size = 0;

        size += sizeof(uint8_t);
        size += sizeof(uint32_t);
        size += sizeof(uint32_t);

        return size;
    }

    void print() const {

        cout << "--------- LIST M2 ----------" << endl;
        cout << "COMMAND CODE: " << printCommandCodeDescription(command_code) << endl;
        cout << "COUNTER: " << counter << endl;
        cout << "FILE SIZE: " << file_list_size << endl;
        cout << "------------------------------" << endl;
    }
};

// ------------------------------------ LIST M3 -------------------------------------

struct ListM3 {

    uint8_t command_code;
    uint32_t counter;
    uint8_t* available_files;          // size = (file_list_size * 30) + (file_list_size - 1)
    int available_files_size;

    ListM3() {}

    ListM3(uint32_t counter, uint8_t* available_files, int available_files_size) {

        this->command_code = FILE_LIST;
        this->counter = counter;
        this->available_files_size = available_files_size;
        this->available_files = new uint8_t[available_files_size];
        memcpy(this->available_files, available_files, available_files_size * sizeof(uint8_t));

    }

    ~ListM3() { delete[] available_files;}

    uint8_t* serialize() const {

        int buffer_size = sizeof(uint8_t) + sizeof(uint32_t) + (available_files_size * sizeof(uint8_t));
        uint8_t* buffer = new uint8_t[buffer_size];

        size_t position = 0;
        memcpy(buffer, &command_code, sizeof(uint8_t));
        position += sizeof(uint8_t);

        memcpy(buffer + position, &counter, sizeof(uint32_t));
        position += sizeof(uint32_t);

        memcpy(buffer + position, available_files, available_files_size * sizeof(uint8_t));

        return buffer;

    }

    static ListM3 deserialize(uint8_t* buffer, int buffer_size) {

        ListM3 listM3;
        listM3.available_files_size = buffer_size - (sizeof(uint8_t) + sizeof(uint32_t));
        
        size_t position = 0;
        memcpy(&listM3.command_code, buffer, sizeof(uint8_t));
        position += sizeof(uint8_t);

        memcpy(&listM3.counter, buffer + position, sizeof(uint32_t));
        position += sizeof(uint32_t);

        listM3.available_files = new uint8_t[listM3.available_files_size];
        memcpy(listM3.available_files, buffer + position, listM3.available_files_size * sizeof(uint8_t));

        return listM3;
    }

    static int getSize(uint32_t file_list_size) {  // file_list_size = number of files

        int size = 0;
        
        size += sizeof(uint8_t);
        size += sizeof(uint32_t);
        size += ((file_list_size * FILE_NAME_SIZE) + (file_list_size - 1)) * sizeof(uint8_t);

        return size;
    }

    void print() const {
        cout << "--------- LIST M3 ----------" << endl;
        cout << "COMMAND CODE: " << printCommandCodeDescription(command_code) << endl;
        cout << "COUNTER: " << counter << endl;
        for (int i = 0; i < available_files_size; ++i)
            cout << (char)available_files[i];
        cout << endl;
        cout << "------------------------------" << endl;
    }
};

// ----------------------------------------------------------------------------------

#endif // _DELETE_H
