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
    char file_name[FILE_NAME_SIZE];

    DownloadM1() {}

    DownloadM1(uint32_t counter, string file_name) {
        this->command_code = DOWNLOAD_REQ;
        this->counter = counter;
        strncpy(this->file_name, file_name.c_str(), FILE_NAME_SIZE);
    }

    uint8_t* serialize() const { 

        uint8_t* buffer = new uint8_t[COMMAND_FIELD_PACKET_SIZE];

        size_t position = 0;
        memcpy(buffer, &this->command_code, sizeof(uint8_t));
        position += sizeof(uint8_t);

        memcpy(buffer + position, &this->counter, sizeof(uint32_t));
        position += sizeof(uint32_t);

        memcpy(buffer + position, this->file_name, FILE_NAME_SIZE * sizeof(uint8_t));
        position += FILE_NAME_SIZE * sizeof(uint8_t);
        
        // add random bytes
        RAND_bytes(buffer + position, COMMAND_FIELD_PACKET_SIZE - position);

        return buffer; 
    }

    static DownloadM1 deserialize(uint8_t* buffer) { 
        DownloadM1 downloadM1;

        size_t position = 0;
        memcpy(&downloadM1.command_code, buffer, sizeof(uint8_t));
        position += sizeof(uint8_t);

        memcpy(&downloadM1.counter, buffer + position, sizeof(uint32_t));
        position += sizeof(uint32_t);

        memcpy(&downloadM1.file_name, buffer + position, FILE_NAME_SIZE * sizeof(char));

        return downloadM1; 
    }

    static int getSize() { 
        int size = 0;

        size += sizeof(uint8_t);
        size += sizeof(uint32_t);
        size += FILE_NAME_SIZE * sizeof(char);

        return size; 
    }

    void print() const {
        cout << "--------- DOWNLOAD M1 ----------" << endl;
        cout << "COMMAND CODE: " << printCommandCodeDescription(this->command_code) << endl;
        cout << "COUNTER: " << this->counter << endl;
        cout << "FILENAME: " << this->file_name << endl;
        cout << "--------------------------------" << endl;
    }
};

// ---------------------------------- DOWNLOAD M2 -----------------------------------

struct DownloadM2 {

    uint8_t command_code;           // FILE_FOUND or FILE_NOT_FOUND
    uint32_t counter;
    uint32_t file_size;

    DownloadM2() {}

    DownloadM2(uint32_t counter, bool success, size_t file_size = 0) {
        
        if (success) {
            this->command_code = FILE_FOUND;
        } else {
            this->command_code = FILE_NOT_FOUND;
        }

        this->counter = counter;
        this->file_size = (file_size < 4UL * 1024 * 1024 * 1024) ? (uint32_t)file_size : 0;
     }

    uint8_t* serialize() const { 
        
        uint8_t* buffer = new uint8_t[DownloadM2::getSize()];

        size_t position = 0;
        memcpy(buffer, &this->command_code, sizeof(uint8_t));
        position += sizeof(uint8_t);

        memcpy(buffer + position, &this->counter, sizeof(uint32_t));
        position += sizeof(uint32_t);

        if (this->command_code == FILE_FOUND) {
            memcpy(buffer + position, &this->file_size, sizeof(uint32_t));
        } else {
            RAND_bytes(buffer + position, sizeof(uint32_t));
        }

        return buffer; 
    }

    static DownloadM2 deserialize(uint8_t* buffer) { 
        
        DownloadM2 downloadM2;

        size_t position = 0;
        memcpy(&downloadM2.command_code, buffer, sizeof(uint8_t));
        position += sizeof(uint8_t);

        memcpy(&downloadM2.counter, buffer + position, sizeof(uint32_t));
        position += sizeof(uint32_t);

        if (downloadM2.command_code == FILE_FOUND)
            memcpy(&downloadM2.file_size, buffer + position, sizeof(uint32_t));
        
        return downloadM2; 
    }

    static int getSize() { 

        int size = 0;
        
        size += sizeof(uint8_t);
        size += sizeof(uint32_t);
        size += sizeof(uint32_t);

        return size; 
    }

    void print() const {
        cout << "--------- DOWNLOAD M2 ----------" << endl;
        cout << "COMMAND CODE: " << printCommandCodeDescription(this->command_code) << endl;
        cout << "COUNTER: " << this->counter << endl;
        if (this->command_code == FILE_FOUND)
            cout << "FILE SIZE: " << this->file_size << " bytes" << endl;
        cout << "--------------------------------" << endl;
    }
};

// --------------------------------- DOWNLOAD M3+i ----------------------------------

struct DownloadMi {

    uint8_t command_code;
    uint32_t counter;
    uint8_t* chunk;

    DownloadMi() {}

    DownloadMi(uint32_t counter, uint8_t* chunk, int chunk_size) {
        this->command_code = FILE_CHUNK;
        this->counter = counter;
        this->chunk = new uint8_t[chunk_size];
        memcpy(this->chunk, chunk, chunk_size * sizeof(uint8_t));
    }   

    ~DownloadMi() { delete[] chunk; }

    uint8_t* serialize(int chunk_size) const { 

        uint8_t* buffer = new uint8_t[DownloadMi::getSize(chunk_size)];

        size_t position = 0;
        memcpy(buffer, &this->command_code, sizeof(uint8_t));
        position += sizeof(uint8_t);

        memcpy(buffer + position, &this->counter, sizeof(uint32_t));
        position += sizeof(uint32_t);

        memcpy(buffer + position, this->chunk, chunk_size * sizeof(uint8_t));

        return buffer; 
    }

    static DownloadMi deserialize(uint8_t* buffer, int chunk_size) { 

        DownloadMi downloadMi;

        size_t position = 0;
        memcpy(&downloadMi.command_code, buffer, sizeof(uint8_t));
        position += sizeof(uint8_t);

        memcpy(&downloadMi.counter, buffer + position, sizeof(uint32_t));
        position += sizeof(uint32_t);

        downloadMi.chunk = new uint8_t[chunk_size];
        memcpy(downloadMi.chunk, buffer + position, chunk_size * sizeof(uint8_t));

        return downloadMi; 
    }

    static int getSize(int chunk_size) { 

        int size = 0;

        size += sizeof(uint8_t);
        size += sizeof(uint32_t);
        size += chunk_size * sizeof(uint8_t);

        return size;
    }

    void print(int chunk_size) const {
        cout << "--------- DOWNLOAD M3+i ----------" << endl;
        cout << "COMMAND CODE: " << printCommandCodeDescription(this->command_code) << endl;
        cout << "COUNTER: " << this->counter << endl;
        cout << "CHUNK CONTENT (" << chunk_size << " bytes): " << endl;
        for (int i = 0; i < chunk_size; ++i)
            cout << hex << (int)chunk[i] << dec;
        cout << endl;
        cout << "----------------------------------" << endl;
    }
};

// ----------------------------------------------------------------------------------

#endif // _DOWNLOAD_H
