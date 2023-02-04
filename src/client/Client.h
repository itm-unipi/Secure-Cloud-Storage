#ifndef _CLIENT_H
#define _CLIENT_H

#include <iostream>
#include <openssl/evp.h>
using namespace std;

class Client {

    string m_username;
    EVP_PKEY* m_long_term_key;

    int login();
    int logout();

public:
    Client();
    Client(const Client&) = delete;
    ~Client();

    int run();
};

#endif  // _CLIENT_H
