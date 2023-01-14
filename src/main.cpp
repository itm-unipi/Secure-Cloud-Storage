#include <stdio.h>
#include <iostream> 
#include <string>
#include "AesCbcCipherBox.h"
using namespace std;

int main() {
    int ret = 0;

    // read the file to encrypt from keyboard:
    string clear_file_name;
    cout << "Please, type the file to encrypt: ";
    getline(cin, clear_file_name);
    if(!cin) { cerr << "Error during input\n"; exit(1); }

    // open the file to encrypt:
    FILE* clear_file = fopen(clear_file_name.c_str(), "rb");
    if(!clear_file) { cerr << "Error: cannot open file '" << clear_file_name << "' (file does not exist?)\n"; exit(1); }

    // get the file size: 
    // (assuming no failures in fseek() and ftell())
    fseek(clear_file, 0, SEEK_END);
    long int plaintext_size = ftell(clear_file);
    fseek(clear_file, 0, SEEK_SET);

    // read the plaintext from file:
    unsigned char* plaintext = (unsigned char*)malloc(plaintext_size);
    if(!plaintext) { cerr << "Error: malloc returned NULL (file too big?)\n"; exit(1); }
    ret = fread(plaintext, 1, plaintext_size, clear_file);
    if(ret < plaintext_size) { cerr << "Error while reading file '" << clear_file_name << "'\n"; exit(1); }
    fclose(clear_file);

    // -----------------------------------------------

    unsigned char* ciphertext = nullptr;
    unsigned char* iv = nullptr;
    int ciphertext_size = 0;
    unsigned char *key = (unsigned char *)"0123456789012345";

    AesCbcCipherBox* encryptor = new AesCbcCipherBox(ENCRYPT, key);
    encryptor->run(plaintext, plaintext_size, ciphertext, ciphertext_size, iv);

    // -----------------------------------------------

    // write the IV and the ciphertext into a '.enc' file:
    string cphr_file_name = clear_file_name + ".enc";
    FILE* cphr_file = fopen(cphr_file_name.c_str(), "wb");
    if(!cphr_file) { cerr << "Error: cannot open file '" << cphr_file_name << "' (no permissions?)\n"; exit(1); }

    ret = fwrite(iv, 1, encryptor->getIvSize(), cphr_file);
    if(ret < encryptor->getIvSize()) { cerr << "Error while writing the file '" << cphr_file_name << "'\n"; exit(1); }

    ret = fwrite(ciphertext, 1, ciphertext_size, cphr_file);
    if(ret < ciphertext_size) { cerr << "Error while writing the file '" << cphr_file_name << "'\n"; exit(1); }
    
    fclose(cphr_file);

    cout << "File '"<< clear_file_name << "' encrypted into file '" << cphr_file_name << "'\n";

    // free(ciphertext);
    delete[] ciphertext;
    delete[] iv;
    free(plaintext);
    delete encryptor;
}