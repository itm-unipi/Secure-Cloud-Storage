#include <iostream>
#include <cstring>
#include <openssl/pem.h>

#include "Client.h"
#include "../packet/Login.h"
#include "../security/DiffieHellman.h"

using namespace std;

Client::Client() {

}

Client::~Client() {

}

int Client::login() {

    // generate the ephemeral key (that contains private and public keys)
    DiffieHellman dh;
    EVP_PKEY* ephemeral_key = dh.generateEphemeralKey();

    // serialize ephemeral key
    uint8_t* serialized_ephemeral_key = nullptr;
    int serialized_ephemeral_key_size;
    int res = DiffieHellman::serializeKey(ephemeral_key, serialized_ephemeral_key, serialized_ephemeral_key_size);
    if (!res) {
        // TODO: errore + delete
    }

    // 1.) send ephemeral key and username
    LoginM1 m1(serialized_ephemeral_key, m_username);
    uint8_t* serialized_packet = m1.serialize();
    res = m_socket->send(serialized_packet, LoginM1::getSize());
    delete[] serialized_packet;
    if (!res) {
        // TODO: errore + delete
    }

    // 2.) receive the result of existence of the user
    serialized_packet = new uint8_t[LoginM2::getSize()];
    res = m_socket->receive(serialized_packet, LoginM2::getSize());
    if (!res) {
        // TODO: errore + delete
    }

    // check if the server found the username
    uint8_t result_check = LoginM2::deserialize(serialized_packet).result;
    delete[] serialized_packet;
    if (!result_check) {
        // TODO: errore + delete
        cerr << "User not exists" << endl;
        return -1;
    }

    cout << "User exists" << endl;

    return 0;
}

int Client::logout() {
    return 0;
}

int Client::run() {

    // --------------- INITIALIZATION ---------------

    string username, password;
    cout << "Insert username: ";
    cin >> m_username;
    cout << "Insert password: ";
    cin >> password;
    
    // sanitize username and password
    static char ok_chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-.@?!#*";
    if (strspn(m_username.c_str(), ok_chars) < strlen(m_username.c_str())) { 
        cerr << "[-] (Client) Not valid username" << endl;
        return -1;
    }
    if (strspn(password.c_str(), ok_chars) < strlen(password.c_str())) { 
        cerr << "[-] (Client) Not valid username" << endl;
        return -1;
    }

    // open the private key PEM file
    string private_key_file = "resources/encrypted_keys/" + m_username + "_key.pem";
    BIO *bio = BIO_new_file(private_key_file.c_str(), "r");
    if (!bio) {
        cerr << "[-] (Client) Failed to open encrypted key PEM file" << endl;
        return -2;
    }
    
    // encrypt and save the long term private key
    m_long_term_key = PEM_read_bio_PrivateKey(bio, 0, 0, (void *)password.c_str());
    BIO_free(bio);

    // connect to the server
    try {
        m_socket = new CommunicationSocket(SERVER_IP, SERVER_PORT);
    } catch (const std::exception& e) {
        std::cerr << "[-] (Client) Exeption: " << e.what() << std::endl;
        return -3;
    }

    // ----------------------------------------------

    login();

    while (1) {
        
        string command;
        cout << "Insert next command: ";
        cin >> command;

        if (command == "list") {

        }

        else if (command == "download") {

        }

        else if (command == "upload") {

        }

        else if (command == "rename") {

        }

        else if (command == "delete") {

        }

        else if (command == "logout") {
            return 0;
        }
        
        else if (command == "exit") {
            return 1;
        }

        else if (command == "help") {
            cout << "----------- COMMANDS -----------" << endl;
            cout << "list: " << endl;
            cout << "download:" << endl;
            cout << "upload:" << endl;
            cout << "rename:" << endl;
            cout << "delete:" << endl;
            cout << "logout:" << endl;
            cout << "exit:" << endl;
            cout << "--------------------------------" << endl;
        }

        else {
            cerr << "[-] (Client) Not valid command" << endl;
        }
        
    }

    return 0;
}