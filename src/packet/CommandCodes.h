#ifndef _COMMANDCODES_H
#define _COMMANDCODES_H

#include <string>
#include <cstdint>
using namespace std;

#define REQ_FAILED      0
#define REQ_SUCCESS     1
#define UPLOAD_REQ      2
#define FILE_CHUNK      3
#define TRANSFER_ACK    4
#define DOWNLOAD_REQ    5
#define DELETE_REQ      6
#define LIST_REQ        7
#define LIST            8
#define RENAME_REQ      9
#define LOGOUT_REQ      10

#define COMMAND_FIELD_PACKET_SIZE 65 * sizeof(uint8_t)          // the longest command packet is the Rename Command (65 byte)

string printCommandCodeDescription(uint8_t code) {

    switch (code)
    {
        case 0:
            return "REQ_FAILED";

        case 1:
            return "REQ_SUCCESS";

        case 10:
            return "LOGOUT_REQ";
    
        default:
            return "UNKNOWN";
    }
}

#endif // _COMMANDCODES_H
