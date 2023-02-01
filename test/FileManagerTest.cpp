#include <iostream>
#include "../src/FileManager.h"
using namespace std;

int main() {
    FileManager file_manager("test.txt", READ);
    FileManager file_manager_2("test_copy.txt", WRITE);
    size_t chunk_size = file_manager.getChunkSize();
    uint8_t* buffer = new uint8_t[chunk_size];

    for (size_t i = 0; i < file_manager.getNumOfChunks(); ++i) {
        if (i == file_manager.getNumOfChunks() - 1)
            chunk_size = file_manager.getLastChunkSize();

        file_manager.readChunk(buffer, chunk_size);
        file_manager_2.writeChunk(buffer, chunk_size);

        cout << "Chunk " << i << " [" << chunk_size << " Byte] copiato" << endl;
    }    
    
    delete[] buffer;
    return 0;
}