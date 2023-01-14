#include <iostream> 
#include <string>
#include <stdlib.h>
#include <stdio.h> // for fopen(), etc.
#include <limits.h> // for INT_MAX
#include <string.h> // for memset()
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
using namespace std;

int main()
{
    int ret; // used for return values
   
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
    long int clear_size = ftell(clear_file);
    fseek(clear_file, 0, SEEK_SET);

    // read the plaintext from file:
    unsigned char* clear_buf = (unsigned char*)malloc(clear_size);
    if(!clear_buf) { cerr << "Error: malloc returned NULL (file too big?)\n"; exit(1); }
    ret = fread(clear_buf, 1, clear_size, clear_file);
    if(ret < clear_size) { cerr << "Error while reading file '" << clear_file_name << "'\n"; exit(1); }
    fclose(clear_file);

    // declare some useful variables:
    const EVP_CIPHER* cipher = EVP_aes_128_cbc();
    int iv_len = EVP_CIPHER_iv_length(cipher);
    int block_size = EVP_CIPHER_block_size(cipher);

    // Assume key is hard-coded (this is not a good thing, but it is not our focus right now)
    unsigned char *key = (unsigned char *)"0123456789012345";
    // Allocate memory for and randomly generate IV:
    unsigned char* iv = (unsigned char*)malloc(iv_len);
    // Seed OpenSSL PRNG
    RAND_poll();
    // Generate 16 bytes at random. That is my IV
    ret = RAND_bytes((unsigned char*)&iv[0],iv_len);
    if(ret!=1){
        cerr <<"Error: RAND_bytes Failed\n";
        exit(1);
    } 
    // check for possible integer overflow in (clear_size + block_size) --> PADDING!
    // (possible if the plaintext is too big, assume non-negative clear_size and block_size):
    if(clear_size > INT_MAX - block_size) { cerr <<"Error: integer overflow (file too big?)\n"; exit(1); }
    // allocate a buffer for the ciphertext:
    int enc_buffer_size = clear_size + block_size;
    unsigned char* cphr_buf = (unsigned char*)malloc(enc_buffer_size);
    if(!cphr_buf) { cerr << "Error: malloc returned NULL (file too big?)\n"; exit(1); }
    
    //Create and initialise the context with used cipher, key and iv
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    if(!ctx){ cerr << "Error: EVP_CIPHER_CTX_new returned NULL\n"; exit(1); }
    ret = EVP_EncryptInit(ctx, cipher, key, iv);
    if(ret != 1){
        cerr <<"Error: EncryptInit Failed\n";
        exit(1);
    }
    int update_len = 0; // bytes encrypted at each chunk
    int total_len = 0; // total encrypted bytes
    
    // Encrypt Update: one call is enough because our file is small.
    ret = EVP_EncryptUpdate(ctx, cphr_buf, &update_len, clear_buf, clear_size);
    if(ret != 1){
        cerr <<"Error: EncryptUpdate Failed\n";
        exit(1);
    }
    total_len += update_len;
    
    //Encrypt Final. Finalize the encryption and adds the padding
    ret = EVP_EncryptFinal(ctx, cphr_buf + total_len, &update_len);
    if(ret != 1){
        cerr <<"Error: EncryptFinal Failed\n";
        exit(1);
    }
    total_len += update_len;
    int cphr_size = total_len;

    // delete the context and the plaintext from memory:
    EVP_CIPHER_CTX_free(ctx);
    // Telling the compiler it MUST NOT optimize the following instruction. 
    // With optimization the memset would be skipped, because of the next free instruction.
    #pragma optimize("", off)
    memset(clear_buf, 0, clear_size);
    #pragma optimize("", on)
    free(clear_buf);
    
    // write the IV and the ciphertext into a '.enc' file:
    string cphr_file_name = clear_file_name + ".enc";
    FILE* cphr_file = fopen(cphr_file_name.c_str(), "wb");
    if(!cphr_file) { cerr << "Error: cannot open file '" << cphr_file_name << "' (no permissions?)\n"; exit(1); }
    
    ret = fwrite(iv, 1, EVP_CIPHER_iv_length(cipher), cphr_file);
    if(ret < EVP_CIPHER_iv_length(cipher)) { cerr << "Error while writing the file '" << cphr_file_name << "'\n"; exit(1); }
    
    ret = fwrite(cphr_buf, 1, cphr_size, cphr_file);
    if(ret < cphr_size) { cerr << "Error while writing the file '" << cphr_file_name << "'\n"; exit(1); }
    
    fclose(cphr_file);

    cout << "File '"<< clear_file_name << "' encrypted into file '" << cphr_file_name << "'\n";

    // deallocate buffers:
    free(cphr_buf);
    free(iv);
    return 0;
}