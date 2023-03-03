#include <iostream>
#include <cstring>
#include <csignal>
using namespace std;

#ifdef SERVER_APPLICATION

#include "server/Server.h"

void serverSignalHandler(int signum) {
    
    switch (signum) {

        case SIGINT:
            cout << "[+] (signalHandler) Server closed" << endl;
            Server::closeInstance();
            exit(signum);
        
        case SIGPIPE:
            cout << "[+] (signalHandler) SIGPIPE intercepted" << endl;
            throw -3;

        default:
            break;
    }
}

#elif CLIENT_APPLICATION

#include "client/Client.h"

void clientSignalHandler(int signum) {
    
    switch (signum) {

        case SIGINT:
            throw -3;
        
        case SIGPIPE:
            throw -4;

        default:
            break;
    }
}

#endif

int main(int argc, char** argv) {

    // read the verbose parameter
    bool verbose = false;
    if (argc > 1) {
        verbose = (strcmp(argv[1], "-v") == 0);
    }

#ifdef SERVER_APPLICATION

    // register the signal handler for SIGINT and SIGPIPE
    signal(SIGINT, serverSignalHandler);
    signal(SIGPIPE, serverSignalHandler);
    
    Server::getInstace()->run(verbose);
    Server::closeInstance();

#elif CLIENT_APPLICATION

    // register the signal handler for SIGINT and SIGPIPE
    // signal(SIGINT, clientSignalHandler);
    signal(SIGPIPE, clientSignalHandler);

    while (1) {
        if (Client(verbose).run() == 1)
            break;
    }

#else
    cerr << "Entity not recognized" << endl;
#endif

    return 0;
}
