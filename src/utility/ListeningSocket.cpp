#include <iostream>
#include <cstring>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#include "ListeningSocket.h"

ListeningSocket::ListeningSocket(string server_ip, int server_port, int max_queue) {
    
    m_listening_socket = socket(AF_INET, SOCK_STREAM, 0);

    // create socket address
    struct sockaddr_in server_address;
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(server_port);
    inet_pton(AF_INET, server_ip.c_str(), &server_address.sin_addr);

    // bind socket with address:port
    int ret = bind(m_listening_socket, (struct sockaddr*)&server_address, sizeof(server_address));
    if (ret == -1) {
        cerr << "[-] (ListeningSocket) Failed to bind socket" << endl;
        return;
    }

    // open the socket
    ret = listen(m_listening_socket, max_queue);
    if (ret == -1) {
        cerr << "[-] (ListeningSocket) Failed to open socket" << endl;
        return;
    }
}

ListeningSocket::~ListeningSocket() {

    close(m_listening_socket);
}

CommunicationSocket* ListeningSocket::accept() {

    struct sockaddr_in client_address;
    int client_address_size = sizeof(client_address);
    int communication_socket_descriptor = ::accept(m_listening_socket, (struct sockaddr*)&client_address, (unsigned int*)&client_address_size);
    
    if (communication_socket_descriptor == -1) {
        cerr << "[-] (ListeningSocket) Failed to accept connection from client" << endl;
        return nullptr;
    }

    return new CommunicationSocket(communication_socket_descriptor);
}