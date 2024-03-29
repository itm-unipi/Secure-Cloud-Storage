#include <iostream>
#include "../src/utility/FileManager.h"
#include "../src/security/AesCbc.h"
using namespace std;

int main() {
    unsigned char *key = (unsigned char *)"01234567890123450123456789012345";
    AesCbc encryptor(ENCRYPT, key);
    AesCbc decryptor(DECRYPT, key);

    FileManager reader("test.txt", READ);
    FileManager writer("test_copy.txt", WRITE);

    size_t chunk_size = reader.getChunkSize();
    uint8_t* buffer = new uint8_t[chunk_size];

    for (size_t i = 0; i < reader.getNumOfChunks(); ++i) {
        if (i == reader.getNumOfChunks() - 1)
            chunk_size = reader.getLastChunkSize();

        unsigned char* plaintext = nullptr;
        unsigned char* ciphertext = nullptr;
        unsigned char* iv = nullptr;
        int ciphertext_size = 0;
        int plaintext_size = 0;

        reader.readChunk(buffer, chunk_size);
        encryptor.run(buffer, chunk_size, ciphertext, ciphertext_size, iv);
        decryptor.run(ciphertext, ciphertext_size, plaintext, plaintext_size, iv);
        writer.writeChunk(plaintext, plaintext_size);

        delete[] plaintext;
        delete[] ciphertext;
        delete[] iv;

        cout << "Chunk " << i << " [" << chunk_size << " Byte] cifrato" << endl;
    }

    delete[] buffer;
    return 0;
}