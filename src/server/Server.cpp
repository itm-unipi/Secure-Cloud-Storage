#include <iostream>

#include "Server.h"
#include "Worker.h"
#include "../security/CertificateStore.h"

using namespace std;

// initialization of Singleton field
Server* Server::m_instance = nullptr;

Server::Server() {

    try {
        // create the listening socket
        m_socket = new ListeningSocket(SERVER_IP, SERVER_PORT, MAX_QUEUE);
    } catch (const std::exception& e) {
        cerr << "[-] (Client) Exeption: " << e.what() << endl;
    }
}

Server::~Server() {
    
    // close the listening socket and the certificate store
    delete m_socket;
    CertificateStore::deleteStore();

    // wait the active threads
    for (auto& thread : m_thread_pool)
        thread.join();
}

int Server::run(bool verbose) {

    while (1) {

        // accept a connection from a new client
        CommunicationSocket* communication_socket = m_socket->accept();
        if (!communication_socket) {
            cerr << "[-] (Server) Failed to accept a connection from a client" << endl;
            continue;
        }

        // create a worker thread that serves the client
        m_thread_pool.push_back(thread([] (CommunicationSocket* socket, bool verbose) {
            // create and start the worker
            Worker(socket, verbose).run();
        }, communication_socket, verbose));
    }

    return 0;
}