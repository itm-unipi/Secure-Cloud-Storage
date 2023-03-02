#ifndef _WORKER_H
#define _WORKER_H

#define LOG(...) if (m_verbose) { cout << "[i] " << __VA_ARGS__ << endl; }

#include "../utility/CommunicationSocket.h"

class Worker {

    bool m_verbose;
    CommunicationSocket* m_socket;
    unsigned char m_session_key[32];
    unsigned char m_hmac_key[32];
    uint32_t m_counter;

    // protocols
    int loginRequest();
    int logoutRequest(uint8_t* plaintext);

    // ----------- BIAGIO -------------
    // --------------------------------

    // ----------- MATTEO -------------
    // --------------------------------

    // ---------- GIANLUCA ------------

    string m_username; 
    int listRequest(uint8_t* plaintext);
    int renameRequest(uint8_t* plaintext);
    int removeRequest(uint8_t* plaintext);

    // --------------------------------

    bool incrementCounter();

public:
    Worker(CommunicationSocket* socket, bool verbose);
    Worker(const Worker&) = delete;
    ~Worker();
    
    int run();
};

#endif // _WORKER_H
