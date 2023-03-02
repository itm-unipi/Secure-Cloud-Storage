#include <iostream>
#include <cmath>
#include <exception>
#include "FileManager.h"

FileManager::FileManager(std::string filename, uint8_t open_type) {

    m_filename = filename;
    m_open_type = open_type;

    // open the file
    if (open_type == READ)
        m_indata.open(filename, std::ios::binary);
    else if (open_type == WRITE)
        m_outdata.open(filename, std::ios::binary);

    // check if the open failed
    if (open_type == READ && !m_indata.is_open()) {
        cerr << "[-] (FileManager) File " << filename << " not exists" << endl;
        throw -1;
    }

    // get the information if is in read mode
    if (open_type == READ) {
        // get file info
        std::streampos begin,end;
        std::ifstream file(filename, std::ios::binary);
        begin = file.tellg();
        file.seekg(0, std::ios::end);
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
    indata.open(file_name, std::ios::binary);

    if (!indata.is_open())
        return false;
    return true;
}