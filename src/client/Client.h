#ifndef _CLIENT_H
#define _CLIENT_H

#define SERVER_IP "localhost"
#define SERVER_PORT 6000

#include <iostream>
#include <openssl/evp.h>

#include "../utility/CommunicationSocket.h"

using namespace std;

class Client {

    string m_username;
    EVP_PKEY* m_long_term_key;
    CommunicationSocket* m_socket;

    int login();
    int logout();

public:
    Client();
    Client(const Client&) = delete;
    ~Client();

    int run();
};

#endif  // _CLIENT_H
