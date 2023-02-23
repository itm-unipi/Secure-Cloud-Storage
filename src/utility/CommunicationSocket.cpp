#include <iostream>
#include <cstring>
#include <exception>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#include "CommunicationSocket.h"

CommunicationSocket::CommunicationSocket(string server_ip, int server_port) {
    // create socket
    m_communication_socket = socket(AF_INET, SOCK_STREAM, 0);

    // create server socket address
    struct sockaddr_in server_address;
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(server_port);
    inet_pton(AF_INET, server_ip.c_str(), &server_address.sin_addr);

    // connect to server socket
    int ret = connect(m_communication_socket, (struct sockaddr*)&server_address, sizeof(server_address));
    if (ret == -1) {
        cerr << "[-] (CommunicationSocket) Failed to connect to server" << endl;
        throw ("Failed to connect to server");
    }
}

CommunicationSocket::CommunicationSocket(int communication_socket_descriptor) 
    : m_communication_socket(communication_socket_descriptor) {}

CommunicationSocket::~CommunicationSocket() {

    close(m_communication_socket);
}

int CommunicationSocket::send(uint8_t* input_buffer, int input_buffer_size) {

    int ret = ::send(m_communication_socket, input_buffer, input_buffer_size, 0);
    if (ret == -1) {
        cerr << "[-] (CommunicationSocket) Failed to send a message" << endl;
        return -1;
    }

    return 0;
}

int CommunicationSocket::receive(uint8_t* output_buffer, int output_buffer_size) {

    int ret = recv(m_communication_socket, (void*)output_buffer, output_buffer_size, MSG_WAITALL);
    
    if (ret <= 0) {
        cerr << "[-] (CommunicationSocket) Failed to receive a message" << endl;
        return -1;
    }

    return 0;
}