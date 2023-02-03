#ifndef _LISTENINGSOCKET_H
#define _LISTENINGSOCKET_H

#include <string>

#include "CommunicationSocket.h"

using namespace std;

class ListeningSocket {

    int m_listening_socket;

public:
    ListeningSocket(string server_ip, int server_port, int max_queue);
    ListeningSocket(const ListeningSocket&) = delete;
    ~ListeningSocket();

    CommunicationSocket* accept();
};

#endif  // _LISTENINGSOCKET_H
