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

// ------------------------------- ENCRYPT -------------------------------

int AesCbcCipherBox::initializeEncrypt() {

    int ret;

    const EVP_CIPHER* cipher = EVP_aes_256_cbc();
    m_iv_size = EVP_CIPHER_iv_length(cipher);
    m_iv = new unsigned char[m_iv_size];
    int block_size = EVP_CIPHER_block_size(cipher);

    RAND_poll();
    ret = RAND_bytes((unsigned char*)&m_iv[0], m_iv_size);
    if (ret!=1) {
        cerr << "[-] (AesCbcCipherBox) RAND_bytes failed" << endl;
        return -1;
    } 

    if (m_plaintext_size > INT_MAX - block_size) { 
        cerr << "[-] (AesCbcCipherBox) integer overflow (file too big?)" << endl; 
        return -1; 
    }

    m_ciphertext_size = m_plaintext_size + block_size;
    m_ciphertext = new unsigned char[m_ciphertext_size];
    if (!m_ciphertext) { 
        cerr << "[-] (AesCbcCipherBox) malloc returned NULL (file too big?)" << endl;
        return -1;
    }
    
    m_ctx = EVP_CIPHER_CTX_new();
    if (!m_ctx) { 
        cerr << "[-] (AesCbcCipherBox) EVP_CIPHER_CTX_new returned NULL" << endl; 
        return -1; 
    }

    ret = EVP_EncryptInit(m_ctx, cipher, m_key, m_iv);
    if (ret != 1) {
        cerr << "[-] (AesCbcCipherBox) EncryptInit failed" << endl;
        return -1;
    }

    m_processed_bytes = 0;
    return 0;
}

int AesCbcCipherBox::updateEncrypt() {
    
    int update_len = 0;
    int ret = EVP_EncryptUpdate(m_ctx, m_ciphertext, &update_len, m_plaintext, m_plaintext_size);    
    if (ret != 1) {
        cerr << "[-] (AesCbcCipherBox) EncryptUpdate failed" << endl;
        return -1;
    }
    
    m_processed_bytes += update_len;
    return 0;
}

int AesCbcCipherBox::finalizeEncrypt() {
    
    int update_len = 0;
    int ret = EVP_EncryptFinal(m_ctx, m_ciphertext + m_processed_bytes, &update_len);
    if (ret != 1) {
        cerr << "[-] (AesCbcCipherBox) EncryptFinal failed" << endl;
        return -1;
    }
    m_processed_bytes += update_len;

    EVP_CIPHER_CTX_free(m_ctx);
    // TODO: controlla se plaintext deve essere riutilizzato e nel caso non azzerare
#pragma optimize("", off)
    memset(m_plaintext, 0, m_plaintext_size);
#pragma optimize("", on)

    m_plaintext = nullptr;
    delete[] m_iv;
    
    return 0;
}

// ------------------------------- DECRYPT -------------------------------

int AesCbcCipherBox::initializeDecrypt() {
    
    int ret;

    const EVP_CIPHER* cipher = EVP_aes_256_cbc();
    m_plaintext = new unsigned char[m_ciphertext_size];

    if (!m_iv || !m_ciphertext || !m_plaintext) { 
        cerr << "[-] (AesCbcCipherBox) Failed to inizialize buffers" << endl; 
        return -1; 
    }

    m_ctx = EVP_CIPHER_CTX_new();
    if (!m_ctx) { 
        cerr << "[-] (AesCbcCipherBox) Failed to initialize context" << endl; 
        return -1; 
    }

    ret = EVP_DecryptInit(m_ctx, cipher, m_key, m_iv);
    if (ret != 1) {
        cerr <<"[-] (AesCbcCipherBox) DecryptInit failed" << endl;
        return -1;
    }

    m_processed_bytes = 0;
    return 0;
}

int AesCbcCipherBox::updateDecrypt() {

    int update_len = 0;
    int ret = EVP_DecryptUpdate(m_ctx, m_plaintext, &update_len, m_ciphertext, m_ciphertext_size);
    if (ret != 1) {
        cerr <<"[-] (AesCbcCipherBox) DecryptUpdate failed" << endl;
        return -1;
    }

    m_processed_bytes += update_len;
    return 0;
}

int AesCbcCipherBox::finalizeDecrypt() {
    int update_len = 0;
    int ret = EVP_DecryptFinal(m_ctx, m_plaintext + m_processed_bytes, &update_len);

    if (ret != 1) {
        cerr <<"[-] (AesCbcCipherBox) DecryptFinal failed" << endl;
        return -1;
    }

    m_processed_bytes += update_len;
    m_plaintext_size = m_processed_bytes;

    EVP_CIPHER_CTX_free(m_ctx);
    delete[] m_iv;

    return 0;
}

// -----------------------------------------------------------------------

void AesCbcCipherBox::run(unsigned char* input_buffer, long int input_buffer_size, unsigned char*& output_buffer, int& output_buffer_size, unsigned char*& iv) {
    
    if (m_type == ENCRYPT) {
        
        m_plaintext = input_buffer;
        m_plaintext_size = input_buffer_size;

        initializeEncrypt();
        iv = new unsigned char[m_iv_size];
        memcpy(iv, m_iv, m_iv_size);
        updateEncrypt();
        finalizeEncrypt();

        output_buffer = m_ciphertext;
        output_buffer_size = m_processed_bytes;
    
    } else if (m_type == DECRYPT) {

        m_ciphertext = input_buffer;
        m_ciphertext_size = input_buffer_size;
        
        m_iv_size = EVP_CIPHER_iv_length(EVP_aes_256_cbc());
        m_iv = new unsigned char[m_iv_size];
        memcpy(m_iv, iv, m_iv_size);

        initializeDecrypt();
        updateDecrypt();
        finalizeDecrypt();

        output_buffer = m_plaintext;
        output_buffer_size = m_plaintext_size;

    } else {
        
        cerr << "[-] (AesCbcCipherBox) Type not valid" << endl;
    
    }
}
