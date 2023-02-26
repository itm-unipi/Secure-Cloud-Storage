#include <iostream>
#include <cstring>
using namespace std;

#ifdef SERVER_APPLICATION

#include <csignal>
#include "server/Server.h"

void signalHandler(int signum) {
    
    cout << "[+] (signalHandler) Server closed" << endl;
    Server::closeInstance();
    exit(signum);
}

#elif CLIENT_APPLICATION

#include "client/Client.h"

#endif

int main(int argc, char** argv) {

    // read the verbose parameter
    bool verbose = false;
    if (argc > 1) {
        verbose = (strcmp(argv[1], "-v") == 0);
    }

#ifdef SERVER_APPLICATION

    // register the signal handler for SIGINT
    signal(SIGINT, signalHandler);
    
    Server::getInstace()->run(verbose);
    Server::closeInstance();

#elif CLIENT_APPLICATION

    while (1) {
        if (Client(verbose).run() == 1)
            break;
    }

#else
    cerr << "Entity not recognized" << endl;
#endif

    return 0;
}
