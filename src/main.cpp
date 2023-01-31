#include <stdio.h>
#include <iostream> 
#include <cstring>
#include "AesCbcCipherBox.h"
using namespace std;

int encrypt() {
    int ret = 0;

    // read the file to encrypt from keyboard:
    string clear_file_name = "test.txt";
    cout << "Please, type the file to encrypt: ";
    // getline(cin, clear_file_name);
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

int decrypt() {
    int ret = 0;

    // read the file to decrypt from keyboard:
    string cphr_file_name = "test.txt.enc";
    cout << "Please, type the file to decrypt: ";
    // getline(cin, cphr_file_name);
    if(!cin) { cerr << "Error during input\n"; exit(1); }

    // open the file to decrypt:
    FILE* cphr_file = fopen(cphr_file_name.c_str(), "rb");
    if(!cphr_file) { cerr << "Error: cannot open file '" << cphr_file_name << "' (file does not exist?)\n"; exit(1); }

    // get the file size: 
    // (assuming no failures in fseek() and ftell())
    fseek(cphr_file, 0, SEEK_END);
    long int cphr_file_size = ftell(cphr_file);
    fseek(cphr_file, 0, SEEK_SET);

    // declare some useful variables:
    const EVP_CIPHER* cipher = EVP_aes_128_cbc();
    int iv_len = EVP_CIPHER_iv_length(cipher);
    
    // Allocate buffer for IV, ciphertext, plaintext
    unsigned char* iv = (unsigned char*)malloc(iv_len);
    int cphr_size = cphr_file_size - iv_len;
    unsigned char* cphr_buf = (unsigned char*)malloc(cphr_size);
    if(!iv || !cphr_buf) { cerr << "Error: malloc returned NULL (file too big?)\n"; exit(1); }

    // read the IV and the ciphertext from file:
    ret = fread(iv, 1, iv_len, cphr_file);
    if(ret < iv_len) { cerr << "Error while reading file '" << cphr_file_name << "'\n"; exit(1); }
    ret = fread(cphr_buf, 1, cphr_size, cphr_file);
    if(ret < cphr_size) { cerr << "Error while reading file '" << cphr_file_name << "'\n"; exit(1); }
    fclose(cphr_file);

    // -----------------------------------------------

    unsigned char* plaintext = nullptr;
    int plaintext_size = 0;
    unsigned char *key = (unsigned char *)"0123456789012345";

    AesCbcCipherBox* decryptor = new AesCbcCipherBox(DECRYPT, key);
    decryptor->run(cphr_buf, cphr_size, plaintext, plaintext_size, iv);

    // -----------------------------------------------

    // write the plaintext into a '.dec' file:
    string clear_file_name = cphr_file_name + ".dec";
    FILE* clear_file = fopen(clear_file_name.c_str(), "wb");
    if(!clear_file) { cerr << "Error: cannot open file '" << clear_file_name << "' (no permissions?)\n"; exit(1); }
    ret = fwrite(plaintext, 1, plaintext_size, clear_file);
    if(ret < plaintext_size) { cerr << "Error while writing the file '" << clear_file_name << "'\n"; exit(1); }
    fclose(clear_file);
    
    // Just out of curiosity, print on stdout the used IV retrieved from file.
    cout<<"Used IV:"<<endl;
    BIO_dump_fp (stdout, (const char *)iv, iv_len);
    
    // delete the plaintext from memory:
    // Telling the compiler it MUST NOT optimize the following instruction. 
    // With optimization the memset would be skipped, because of the next free instruction.
#pragma optimize("", off)
    memset(plaintext, 0, plaintext_size);
#pragma optimize("", on)
    delete[] plaintext;

    cout << "File '"<< cphr_file_name << "' decrypted into file '" << clear_file_name << "', clear size is " << plaintext_size << " bytes\n";

    // deallocate buffers:
    free(iv);
    free(cphr_buf);

    delete decryptor;

    return 0;
}

int main() {
    encrypt();
    decrypt();
}