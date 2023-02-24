#ifndef _WORKER_H
#define _WORKER_H

#define LOG(...) if (m_verbose) { cout << "[i] " << __VA_ARGS__ << endl; }

#include "../utility/CommunicationSocket.h"

class Worker {

    bool m_verbose;
    CommunicationSocket* m_socket;
    unsigned char m_session_key[32];
    unsigned char m_hmac_key[32];

    // protocols
    int loginRequest();
    int logoutRequest();

    bool incrementCounter(uint32_t& counter);

public:
    Worker(CommunicationSocket* socket, bool verbose);
    Worker(const Worker&) = delete;
    ~Worker();
    
    int run();
};

#endif // _WORKER_H
