#include <iostream>
#include <cstring>
#include <openssl/pem.h>

#include "Client.h"

using namespace std;

Client::Client() {

}

Client::~Client() {

}

int Client::login() {
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