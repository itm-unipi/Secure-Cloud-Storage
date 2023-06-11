#include <iostream>
#include <cstring>
#include <csignal>

#include "./Server.h"

using namespace std;

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

int main(int argc, char** argv) {

    // read the verbose parameter
    bool verbose = false;
    if (argc > 1) {
        verbose = (strcmp(argv[1], "-v") == 0);
    }

    // register the signal handler for SIGINT and SIGPIPE
    signal(SIGINT, serverSignalHandler);
    signal(SIGPIPE, serverSignalHandler);
    
    Server::getInstance()->run(verbose);
    Server::closeInstance();

    return 0;
}
