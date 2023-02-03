#include <iostream>
#include <cstring>
#include <chrono>
#include <thread>

#include "../src/utility/ListeningSocket.h"

#define MSG "test\0"
#define MSG_SIZE 5

using namespace std;    

void server() {

    ListeningSocket listening_socket("localhost", 5000, 10);
    CommunicationSocket* communication_socket = listening_socket.accept();

    for (int i = 0; i < 3; ++i) {
        unsigned char msg[MSG_SIZE];
        int msg_size = MSG_SIZE;

        communication_socket->receive(msg, msg_size);
        cout << "RECEIVED: " << msg << endl;

        if (!strcmp((const char*)msg, MSG))
            cout << "STRINGA UGUALE" << endl;
    }

    delete communication_socket;
}

void client() {

    this_thread::sleep_for(chrono::seconds(2));
    CommunicationSocket communication_socket("localhost", 5000);

    unsigned char* msg = (unsigned char*)MSG;
    int msg_size = MSG_SIZE;

    for (int i = 0; i < 3; ++i)
        communication_socket.send(msg, msg_size);
}

int main() {

    thread server_thread(server);
    thread client_thread(client);

    server_thread.join();
    client_thread.join();

    return 0;
}
