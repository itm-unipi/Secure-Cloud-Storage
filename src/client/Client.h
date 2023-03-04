#ifndef _CLIENT_H
#define _CLIENT_H

#define LOG(...) if (m_verbose) { cout << "[i] " << __VA_ARGS__ << endl; }

#include <iostream>
#include <cstring>
#include <openssl/evp.h>

#include "../utility/CommunicationSocket.h"
#include "../security/AesCbc.h"
#include "../security/Hmac.h"

using namespace std;

class Client {

    string m_username;
    CommunicationSocket* m_socket;
    EVP_PKEY* m_long_term_key;
    unsigned char m_session_key[AES_KEY_SIZE];
    unsigned char m_hmac_key[HMAC_DIGEST_SIZE];
    uint32_t m_counter;
    bool m_verbose;

    int login();
    int logout();
    int download(string file_name);
    int upload(string file_name);
    int list();
    int rename(string file_name, string new_file_name);
    int remove(string file_name);

    void incrementCounter();

    static void safeDelete(uint8_t* buffer, int size) {
        // overwrite with 0 and deallocate the buffer
        #pragma optimize("", off)
        memset(buffer, 0, size);
        #pragma optimize("", on)
        delete[] buffer;
    }

public:
    Client(bool verbose);
    Client(const Client&) = delete;
    ~Client();

    int run();
};

#endif  // _CLIENT_H
