#include <iostream>
#include <cstring>
#include <csignal>

#include "./Client.h"

using namespace std;

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

int main(int argc, char** argv) {

    // read the verbose parameter
    bool verbose = false;
    if (argc > 1) {
        verbose = (strcmp(argv[1], "-v") == 0);
    }

    // register the signal handler for SIGINT and SIGPIPE
    // signal(SIGINT, clientSignalHandler);
    signal(SIGPIPE, clientSignalHandler);

    while (1) {
        if (Client(verbose).run() == 1)
            break;
    }

    return 0;
}
