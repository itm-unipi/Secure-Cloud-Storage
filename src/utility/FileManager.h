#ifndef _FILEMANAGER_H
#define _FILEMANAGER_H

#include <fstream>
using namespace std;

#define READ 0
#define WRITE 1

class FileManager {

    ifstream m_indata;
    ofstream m_outdata;

    string m_file_name;
    uint8_t m_open_type;
    size_t m_chunk_size, m_file_size, m_last_chunk_size, m_num_of_chunks;

public:
    FileManager(string file_name, uint8_t open_type);
    FileManager(const FileManager&) = delete;
    ~FileManager();

    int readChunk(uint8_t* buffer, size_t size);
    int writeChunk(uint8_t* buffer, size_t size);

    size_t getChunkSize() { return m_chunk_size; }
    size_t getFileSize() { return m_file_size; }
    size_t getLastChunkSize() { return m_last_chunk_size; }
    size_t getNumOfChunks() { return m_num_of_chunks; }
    
    void calculateFileInfo(size_t size);

    static bool exists(string file_name);
    static int sanitizeFileName(string file_name);
};

#endif  // _FILEMANAGER_H
