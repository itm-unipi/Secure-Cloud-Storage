#ifndef _CLIENT_H
#define _CLIENT_H

#define SERVER_IP "localhost"
#define SERVER_PORT 6000

#define LOG(...) if (m_verbose) { cout << "[i] " << __VA_ARGS__ << endl; }

#include <iostream>
#include <openssl/evp.h>

#include "../utility/CommunicationSocket.h"

using namespace std;

class Client {

    string m_username;
    CommunicationSocket* m_socket;
    EVP_PKEY* m_long_term_key;
    unsigned char m_session_key[32];
    unsigned char m_hmac_key[32];
    bool m_verbose;

    int login();
    int logout();

public:
    Client(bool verbose);
    Client(const Client&) = delete;
    ~Client();

    int run();
};

#endif  // _CLIENT_H
