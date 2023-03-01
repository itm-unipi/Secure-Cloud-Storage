#ifndef _WORKER_H
#define _WORKER_H

#define LOG(...) if (m_verbose) { cout << "[i] " << __VA_ARGS__ << endl; }

#include "../utility/CommunicationSocket.h"

class Worker {

    string m_username;
    bool m_verbose;
    CommunicationSocket* m_socket;
    unsigned char m_session_key[32];
    unsigned char m_hmac_key[32];
    uint32_t m_counter;
    string m_username;

    // protocols
    int loginRequest();
    int logoutRequest(uint8_t* plaintext);

    // ----------- BIAGIO -------------
    int downloadRequest(uint8_t* plaintext);
    // --------------------------------

    // ----------- MATTEO -------------
    int uploadRequest(uint8_t* plaintext);
    // --------------------------------

    // ---------- GIANLUCA ------------
    // --------------------------------

    bool incrementCounter();

public:
    Worker(CommunicationSocket* socket, bool verbose);
    Worker(const Worker&) = delete;
    ~Worker();
    
    int run();
};

#endif // _WORKER_H
