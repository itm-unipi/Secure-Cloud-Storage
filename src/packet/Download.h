#ifndef _DOWNLOAD_H
#define _DOWNLOAD_H

#include <iostream>
#include <string>
#include <cstdint>
#include <cstring>
#include <openssl/rand.h>

#include "../utility/FileManager.h"
#include "./CommandCodes.h"

using namespace std;

// ---------------------------------- DOWNLOAD M1 -----------------------------------

struct DownloadM1 {

    uint8_t command_code;
    uint32_t counter;
    char file_name[30];

    DownloadM1() {}

    DownloadM1(uint32_t counter, string file_name) {}

    uint8_t* serialize() const { return nullptr; }

    static DownloadM1 deserialize(uint8_t* buffer) { return DownloadM1(); }

    static int getSize() { return 0; }

    void print() const {}
};

// ---------------------------------- DOWNLOAD M2 -----------------------------------

struct DownloadM2 {

    uint8_t command_code;           // FILE_FOUND or FILE_NOT_FOUND
    uint32_t counter;
    uint32_t file_size;

    DownloadM2() {}

    DownloadM2(uint32_t counter, bool success, uint32_t file_size = 0) { }

    uint8_t* serialize() const { return nullptr; }

    static DownloadM2 deserialize(uint8_t* buffer) { return DownloadM2(); }

    static int getSize() { return 0; }

    void print() const {}
};

// --------------------------------- DOWNLOAD M3+i ----------------------------------

struct DownloadMi {

    uint8_t command_code;
    uint32_t counter;
    uint8_t chunk[CHUNK_SIZE];

    DownloadMi() {}

    DownloadMi(uint32_t counter, uint8_t* chunk, int chunk_size) {}   // se la chunk_size è < della macro CHUNK_SIZE -> aggiungere byte randomici

    uint8_t* serialize() const { return nullptr; }

    static DownloadMi deserialize(uint8_t* buffer) { return DownloadMi(); }

    static int getSize() { return 0; }

    void print() const {}
};

// ----------------------------------------------------------------------------------

#endif // _DOWNLOAD_H
