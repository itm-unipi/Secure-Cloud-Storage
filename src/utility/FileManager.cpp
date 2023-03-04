#include <iostream>
#include <cmath>
#include <exception>
#include <cstring>

#include "FileManager.h"
#include "../../resources/Config.h"

FileManager::FileManager(string file_name, uint8_t open_type) {

    m_file_name = file_name;
    m_open_type = open_type;

    // check if the file already exists in write mode
    if (open_type == WRITE && exists(file_name)) {
        cerr << "[-] (FileManager) File " << file_name << " already exists" << endl;
        throw -1;
    }

    // open the file
    if (open_type == READ)
        m_indata.open(file_name, ios::binary);
    else if (open_type == WRITE)
        m_outdata.open(file_name, ios::binary);

    // check if the open failed in read mode
    if (open_type == READ && !m_indata.is_open()) {
        cerr << "[-] (FileManager) File " << file_name << " not exists" << endl;
        throw -2;
    }

    // get the information if is in read mode
    if (open_type == READ) {
        // get file info
        streampos begin,end;
        ifstream file(file_name, ios::binary);
        begin = file.tellg();
        file.seekg(0, ios::end);
        end = file.tellg();
        file.close();

        // compute lenght of file, number of chunks and size of last chunk
        m_chunk_size = CHUNK_SIZE;
        m_file_size = end - begin;
        m_num_of_chunks = ceil((double)m_file_size / (double)m_chunk_size);
        m_last_chunk_size = m_file_size % m_chunk_size != 0 ? m_file_size - ((m_num_of_chunks - 1) * m_chunk_size) : m_chunk_size;
    }
}

FileManager::~FileManager() {

    if (m_open_type == READ)
        m_indata.close();
    else if (m_open_type == WRITE)
        m_outdata.close();
}

int FileManager::readChunk(uint8_t* buffer, size_t size) {

    if (m_open_type == READ) {
        m_indata.read((char*)buffer, size);
    } else {
        cerr << "[-] (FileManager) File manager not in read mode" << endl;
        return -1;
    }

    return 0;
}

int FileManager::writeChunk(uint8_t* buffer, size_t size) {

    if (m_open_type == WRITE) {
        m_outdata.write((char*)buffer, size);
    } else {
        cerr << "[-] (FileManager) File manager not in write mode" << endl;
        return -1;
    }

    return 0;
}

void FileManager::calculateFileInfo(size_t size) {
    m_chunk_size = CHUNK_SIZE;
    m_file_size = size;
    m_num_of_chunks = ceil((double)m_file_size / (double)m_chunk_size);
    m_last_chunk_size = m_file_size % m_chunk_size != 0 ? m_file_size - ((m_num_of_chunks - 1) * m_chunk_size) : m_chunk_size;
}

bool FileManager::exists(string file_name) {

    // try to open the file
    ifstream indata;
    indata.open(file_name, ios::binary);

    if (!indata.is_open())
        return false;
    return true;
}


int FileManager::sanitizeFileName(string file_name) {

    // compare string with the characters in the whitelist
    char whitelist[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-.@?!#*";
    if (strspn(file_name.c_str(), whitelist) < strlen(file_name.c_str()))
        return -1;

    // check if the file name is '.'
    if (file_name == ".") 
        return -2;

    // check if the file name is '..'
    if (file_name == "..")
        return -3;

    // check if the file name is too long
    if (file_name.length() >= FILE_NAME_SIZE)
        return -4;

    return 0;
}