#ifndef _WORKER_H
#define _WORKER_H

#define LOG(...) if (m_verbose) { cout << "[i] " << __VA_ARGS__ << endl; }

#include <cstring>

#include "../utility/CommunicationSocket.h"
#include "../security/AesCbc.h"
#include "../security/Hmac.h"

class Worker {

    string m_username;
    bool m_verbose;
    CommunicationSocket* m_socket;
    unsigned char m_session_key[AES_KEY_SIZE];
    unsigned char m_hmac_key[HMAC_DIGEST_SIZE];
    uint32_t m_counter;

    // protocols
    int loginRequest();
    int logoutRequest(uint8_t* plaintext);
    int downloadRequest(uint8_t* plaintext);
    int uploadRequest(uint8_t* plaintext);
    int listRequest(uint8_t* plaintext);
    int renameRequest(uint8_t* plaintext);
    int removeRequest(uint8_t* plaintext);

    void incrementCounter();

    static void safeDelete(uint8_t* buffer, int size) {
        // overwrite with 0 and deallocate the buffer
        #pragma optimize("", off)
        memset(buffer, 0, size);
        #pragma optimize("", on)
        delete[] buffer;
    }

public:
    Worker(CommunicationSocket* socket, bool verbose);
    Worker(const Worker&) = delete;
    ~Worker();
    
    int run();
};

#endif // _WORKER_H
