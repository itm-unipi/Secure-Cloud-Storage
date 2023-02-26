#ifndef _RENAME_H
#define _RENAME_H

#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>

#include "./CommandCodes.h"

using namespace std;

// ----------------------------------- RENAME M1 ------------------------------------

struct RenameM1 {

    uint8_t command_code;
    uint32_t counter;
    char file_name[30];
    char new_file_name[30];

    RenameM1() {}

    RenameM1(uint32_t counter, string file_name, string new_file_name) {}

    uint8_t* serialize() const { return nullptr; }

    static RenameM1 deserialize(uint8_t* buffer) { return RenameM1(); }

    static int getSize() { return 0; }

    void print() const {}
};

// ----------------------------------------------------------------------------------

#endif // _RENAME_H
