#ifndef _WORKER_H
#define _WORKER_H

#include "../utility/CommunicationSocket.h"

class Worker {

    CommunicationSocket* m_socket;
    unsigned char m_session_key[256];
    unsigned char m_hmac_key[256];

    // protocols
    int loginRequest();
    int logoutRequest();

public:
    Worker(CommunicationSocket* socket);
    Worker(const Worker&) = delete;
    ~Worker();
    
    int run();
};

#endif // _WORKER_H
