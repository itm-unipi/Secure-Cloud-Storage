#include <iostream>
#include <cstring>
#include <chrono>
#include <thread>
#include <arpa/inet.h>

#include "../src/utility/ListeningSocket.h"

#define MSG "test\0"
#define MSG_SIZE 5

using namespace std;

// ------------ PACKET EXAMPLE ------------

struct Packet {

    uint8_t iv[16];
    uint8_t type;
    uint32_t counter;
    char filename[30];
    char new_filename[30];
    uint8_t hmac[32];

    Packet() {}

    Packet(unsigned char* iv, uint8_t type, uint32_t counter, string filename, string new_filename, unsigned char* hmac) {

        memcpy(this->iv, iv, 16);
        this->type = type;
        this->counter = counter;

        memset(this->filename, 0, sizeof(this->filename));
        strcpy(this->filename, filename.c_str());

        memset(this->new_filename, 0, sizeof(this->new_filename));
        strcpy(this->new_filename, new_filename.c_str());

        memcpy(this->hmac, hmac, 32);
    }

    uint8_t* serialize() const {
        
        uint8_t* buffer = new uint8_t[Packet::getSize()];
        
        size_t position = 0;
        memcpy(buffer, iv, 16 * sizeof(uint8_t));
        position += 16 * sizeof(uint8_t);

        memcpy(buffer + position, &type, sizeof(uint8_t));
        position += sizeof(uint8_t);

        uint32_t portable_counter = htonl(counter);
        memcpy(buffer + position, &portable_counter, sizeof(uint32_t));
        position += sizeof(uint32_t);

        memcpy(buffer + position, filename, 30 * sizeof(char));
        position += 30 * sizeof(char);

        memcpy(buffer + position, new_filename, 30 * sizeof(char));
        position += 30 * sizeof(char);

        memcpy(buffer + position, hmac, 32 * sizeof(uint8_t));
        position += 32 * sizeof(uint8_t);

        return buffer;
    }

    static Packet deserialize(uint8_t* buffer) {
        
        Packet packet;
        
        size_t position = 0;
        memcpy(packet.iv, buffer, 16 * sizeof(uint8_t));
        position += 16 * sizeof(uint8_t);

        memcpy(&packet.type, buffer + position, sizeof(uint8_t));
        position += sizeof(uint8_t);

        uint32_t portable_counter;
        memcpy(&portable_counter, buffer + position, sizeof(uint32_t));
        packet.counter = ntohl(portable_counter);
        position += sizeof(uint32_t);

        memcpy(packet.filename, buffer + position, 30 * sizeof(char));
        position += 30 * sizeof(char);

        memcpy(packet.new_filename, buffer + position, 30 * sizeof(char));
        position += 30 * sizeof(char);

        memcpy(packet.hmac, buffer + position, 32 * sizeof(uint8_t));

        return packet;
    }

    static int getSize() {
        
        int size = 0;

        size += 16 * sizeof(uint8_t);
        size += sizeof(uint8_t);
        size += sizeof(uint32_t);
        size += 30 * sizeof(char);
        size += 30 * sizeof(char);
        size += 32 * sizeof(uint8_t);

        return size;
    }

    void print() const {

        cout << "\nPACKET:" << endl;
        cout << "IV: " << iv << endl;
        cout << "TYPE: " << (int)type << endl;
        cout << "COUNTER: " << counter << endl;
        cout << "FILENAME: " << filename << endl;
        cout << "NEW FILENAME: " << new_filename << endl;
        cout << "HMAC: " << hmac << endl;
    }
};

// ----------------------------------------

void server() {

    ListeningSocket listening_socket("localhost", 5000, 10);
    CommunicationSocket* communication_socket = listening_socket.accept();

    // invio ripetuto del messaggio
    for (int i = 0; i < 3; ++i) {
        uint8_t msg[MSG_SIZE];
        int msg_size = MSG_SIZE;

        communication_socket->receive(msg, msg_size);
        cout << "RECEIVED: " << msg << endl;

        if (!strcmp((const char*)msg, MSG))
            cout << "STRINGA UGUALE" << endl;
    }

    // creazione parametri da mettere nel pacchetto
    unsigned char* iv = (unsigned char*)"012345678912345";
    uint8_t type = 2;
    uint32_t counter = 100000;
    string filename = "a.txt";
    string new_filename = "b.txt";
    unsigned char* hmac = (unsigned char*)"0123456789123456012345678912345";

    // creazione della struct del pacchetto
    Packet packet(iv, type, counter, filename, new_filename, hmac);

    uint8_t* serialized_packet = packet.serialize();
    communication_socket->send(serialized_packet, Packet::getSize());

    delete[] serialized_packet; 
    delete communication_socket;
}

void client() {

    this_thread::sleep_for(chrono::seconds(2));
    CommunicationSocket communication_socket("localhost", 5000);

    uint8_t* msg = (uint8_t*)MSG;
    int msg_size = MSG_SIZE;

    for (int i = 0; i < 3; ++i)
        communication_socket.send(msg, msg_size);

    uint8_t serialized_packet[Packet::getSize()];
    communication_socket.receive(serialized_packet, Packet::getSize());
    Packet packet = Packet::deserialize(serialized_packet);
    packet.print();
}

int main() {

    thread server_thread(server);
    thread client_thread(client);

    server_thread.join();
    client_thread.join();

    return 0;
}
