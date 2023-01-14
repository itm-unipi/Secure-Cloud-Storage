#include <iostream>
#include <cstring>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>

#include "AesCbcCipherBox.h"

using namespace std;

AesCbcCipherBox::AesCbcCipherBox(uint8_t type, unsigned char* key) {
    
    m_type = type;
    m_key = new unsigned char[BLOCK_SIZE];
    memcpy(m_key, key, BLOCK_SIZE);
}

AesCbcCipherBox::~AesCbcCipherBox() {
    
    #pragma optimize("", off)
    memset(m_key, 0, BLOCK_SIZE);
    #pragma optimize("", on)
    delete[] m_key;
}

int AesCbcCipherBox::initialize() {

    int ret;

    const EVP_CIPHER* cipher = EVP_aes_128_cbc();
    m_iv_size = EVP_CIPHER_iv_length(cipher);
    int block_size = EVP_CIPHER_block_size(cipher);

    m_iv = (unsigned char*)malloc(m_iv_size);

    RAND_poll();
    ret = RAND_bytes((unsigned char*)&m_iv[0], m_iv_size);
    if (ret!=1) {
        cerr << "Error: RAND_bytes Failed\n";
        return -1;
    } 

    if (m_plaintext_size > INT_MAX - block_size) { 
        cerr << "Error: integer overflow (file too big?)\n"; 
        return -1; 
    }

    m_ciphertext_size = m_plaintext_size + block_size;
    m_ciphertext = new unsigned char[m_ciphertext_size];
    if (!m_ciphertext) { 
        cerr << "Error: malloc returned NULL (file too big?)\n";
        return -1;
    }
    
    m_ctx = EVP_CIPHER_CTX_new();
    if (!m_ctx) { 
        cerr << "Error: EVP_CIPHER_CTX_new returned NULL\n"; 
        return -1; 
    }

    ret = EVP_EncryptInit(m_ctx, cipher, m_key, m_iv);
    if (ret != 1) {
        cerr << "Error: EncryptInit Failed\n";
        return -1;
    }

    m_processed_bytes = 0;
    return 0;
}

int AesCbcCipherBox::update() {
    
    int update_len = 0;
    int ret = EVP_EncryptUpdate(m_ctx, m_ciphertext, &update_len, m_plaintext, m_plaintext_size);    
    if (ret != 1) {
        cerr << "Error: EncryptUpdate Failed\n";
        return -1;
    }
    
    m_processed_bytes += update_len;
    return 0;
}

int AesCbcCipherBox::finalize() {
    
    int update_len = 0;
    int ret = EVP_EncryptFinal(m_ctx, m_ciphertext + m_processed_bytes, &update_len);
    if (ret != 1) {
        cerr << "Error: EncryptFinal Failed\n";
        return -1;
    }
    m_processed_bytes += update_len;

    EVP_CIPHER_CTX_free(m_ctx);
    // TODO: controlla se plaintext deve essere riutilizzato e nel caso non azzerare
    #pragma optimize("", off)
    memset(m_plaintext, 0, m_plaintext_size);
    #pragma optimize("", on)
    /* TODO: falla fuori
    free(m_plaintext);
    */

    m_plaintext = nullptr;
    // free(m_ciphertext);
    free(m_iv);
    
    return 0;
}

void AesCbcCipherBox::run(unsigned char* input_buffer, long int input_buffer_size, unsigned char*& output_buffer, int& output_buffer_size, unsigned char*& iv) {
    m_plaintext = input_buffer;
    m_plaintext_size = input_buffer_size;

    initialize();
    iv = new unsigned char[m_iv_size];
    memcpy(iv, m_iv, m_iv_size);
    update();
    finalize();

    output_buffer = m_ciphertext;
    output_buffer_size = m_processed_bytes;
}
