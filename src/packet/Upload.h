#ifndef _UPLOAD_H
#define _UPLOAD_H

#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>
#include <openssl/rand.h>

#include "../utility/FileManager.h"
#include "./CommandCodes.h"

using namespace std;

// ----------------------------------- UPLOAD M1 ------------------------------------

struct UploadM1 {

    uint8_t command_code;
    uint32_t counter;
    char file_name[30];
    uint32_t file_size;         // 0 represents 4GB

    UploadM1() {}

    UploadM1(uint32_t counter, string file_name, uint32_t file_size) {}

    uint8_t* serialize() const { return nullptr; }

    static UploadM1 deserialize(uint8_t* buffer) { return UploadM1(); }

    static int getSize() { return 0; }

    void print() const {}
};

// ---------------------------------- UPLOAD M3+i -----------------------------------

struct UploadMi {

    uint8_t command_code;
    uint32_t counter;
    uint8_t chunk[CHUNK_SIZE];

    UploadMi() {}

    UploadMi(uint32_t counter, uint8_t* chunk, int chunk_size) {}   // se la chunk_size è < della macro CHUNK_SIZE -> aggiungere byte randomici

    uint8_t* serialize() const { return nullptr; }

    static UploadMi deserialize(uint8_t* buffer) { return UploadMi(); }

    static int getSize() { return 0; }

    void print() const {}
};

// ----------------------------------- UPLOAD Mn ------------------------------------

struct UploadMn {

    uint8_t command_code;
    uint32_t counter;
    uint8_t status;

    UploadMn() {}

    UploadMn(uint32_t counter, uint8_t status) {}

    uint8_t* serialize() const { return nullptr; }

    static UploadMn deserialize(uint8_t* buffer) { return UploadMn(); }

    static int getSize() { return 0; }

    void print() const {}
};

// ----------------------------------------------------------------------------------

#endif // _UPLOAD_H
