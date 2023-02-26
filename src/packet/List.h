#ifndef _DELETE_H
#define _DELETE_H

#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>

#include "./CommandCodes.h"

using namespace std;

// ------------------------------------ LIST M1 -------------------------------------

struct ListM1 {

    uint8_t command_code;
    uint32_t counter;

    ListM1() {}

    ListM1(uint32_t counter, string file_name) {}

    uint8_t* serialize() const { return nullptr; }

    static ListM1 deserialize(uint8_t* buffer) { return ListM1(); }

    static int getSize() { return 0; }

    void print() const {}
};

// ------------------------------------ LIST M2 -------------------------------------

struct ListM2 {

    uint8_t command_code;
    uint32_t counter;
    uint32_t file_list_size;

    ListM2() {}

    ListM2(uint32_t counter, string file_name) {}

    uint8_t* serialize() const { return nullptr; }

    static ListM2 deserialize(uint8_t* buffer) { return ListM2(); }

    static int getSize() { return 0; }

    void print() const {}
};

// ------------------------------------ LIST M3 -------------------------------------

struct ListM3 {

    uint8_t command_code;
    uint32_t counter;
    char* available_files;          // size = (file_list_size * 30) + (file_list_size - 1)

    ListM3() {}

    ListM3(uint32_t counter, string file_name) {}

    ~ListM3() { delete[] available_files; }

    uint8_t* serialize() const { return nullptr; }

    static ListM3 deserialize(uint8_t* buffer) { return ListM3(); }

    static int getSize() { return 0; }

    void print() const {}
};

// ----------------------------------------------------------------------------------

#endif // _DELETE_H
