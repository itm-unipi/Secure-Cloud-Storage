#ifndef _COMMUNICATIONSOCKET_H
#define _COMMUNICATIONSOCKET_H

#include <string>
using namespace std;

class CommunicationSocket {

    int m_communication_socket;

public:
    CommunicationSocket(string server_ip, int server_port);
    CommunicationSocket(int communication_socket_descriptor);
    CommunicationSocket(const CommunicationSocket&) = delete;
    ~CommunicationSocket();

    int send(unsigned char* input_buffer, int input_buffer_size);
    int receive(unsigned char* output_buffer, int output_buffer_size);
};

#endif  // _COMMUNICATIONSOCKET_H
