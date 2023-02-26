#ifndef _DELETE_H
#define _DELETE_H

#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>

#include "./CommandCodes.h"

using namespace std;

// ----------------------------------- DELETE M1 ------------------------------------

struct DeleteM1 {

    uint8_t command_code;
    uint32_t counter;
    char file_name[30];

    DeleteM1() {}

    DeleteM1(uint32_t counter, string file_name) {}

    uint8_t* serialize() const { return nullptr; }

    static DeleteM1 deserialize(uint8_t* buffer) { return DeleteM1(); }

    static int getSize() { return 0; }

    void print() const {}
};

// ----------------------------------------------------------------------------------

#endif // _DELETE_H
