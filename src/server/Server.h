#ifndef _SERVER_H
#define _SERVER_H

class Server {

    // protocols
    int loginRequest();
    int logoutRequest();

public:
    Server();
    Server(const Server&) = delete;
    ~Server();

    void run();
};

#endif  // _SERVER_H
