#ifndef _SERVER_H
#define _SERVER_H

#include <vector>
#include <thread>
#include "../utility/ListeningSocket.h"

class Server {

    ListeningSocket* m_socket;
    vector<thread> m_thread_pool;

    static Server* m_instance;

public:
    Server();
    Server(const Server&) = delete;
    ~Server();

    int run(bool verbose);

    static Server* getInstace() {
        if (!m_instance)
            m_instance = new Server();
        return m_instance;
    }

    static void closeInstance() {
        if (m_instance) {
            delete m_instance;
            m_instance = nullptr;
        }
    }
};

#endif  // _SERVER_H
