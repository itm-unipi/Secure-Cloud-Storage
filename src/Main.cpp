#include <iostream>
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

int main() {

#ifdef SERVER_APPLICATION

    // register the signal handler for SIGINT
    signal(SIGINT, signalHandler);
    
    Server::getInstace()->run();
    Server::closeInstance();

#elif CLIENT_APPLICATION

    while (1) {
        if (Client().run() == 1)
            break;
    }
    

#else
    cerr << "Entità non riconosciuta" << endl;
#endif

    return 0;
}
