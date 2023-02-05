#ifndef _SERVER_H
#define _SERVER_H

#define SERVER_IP "localhost"
#define SERVER_PORT 6000
#define MAX_QUEUE 10

#include <vector>
#include <thread>
#include "../utility/ListeningSocket.h"

class Server {

    ListeningSocket* m_socket;
    vector<thread> m_thread_pool;

public:
    Server();
    Server(const Server&) = delete;
    ~Server();

    int run();
};

#endif  // _SERVER_H
