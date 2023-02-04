#include <iostream>
using namespace std;

#ifdef SERVER_APPLICATION
    #include "server/Server.h"
#elif CLIENT_APPLICATION
    #include "client/Client.h"
#endif

int main() {

#ifdef SERVER_APPLICATION
    


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
