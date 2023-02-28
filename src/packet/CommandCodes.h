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
#define FILE_FOUND      6
#define FILE_NOT_FOUND  7
#define DELETE_REQ      8
#define FILE_LIST_REQ   9
#define FILE_LIST_SIZE  10
#define FILE_LIST       11
#define RENAME_REQ      12
#define LOGOUT_REQ      13

#define COMMAND_FIELD_PACKET_SIZE 65 * sizeof(uint8_t)          // the longest command packet is the Rename Command (65 byte)

string printCommandCodeDescription(uint8_t code) {

    switch (code)
    {
        case 0:
            return "REQ_FAILED";

        case 1:
            return "REQ_SUCCESS";

        case 2:
            return "UPLOAD_REQ";

        case 3:
            return "FILE_CHUNK";

        case 4:
            return "TRANSFER_ACK";

        case 13:
            return "LOGOUT_REQ";
    
        default:
            return "UNKNOWN";
    }
}

#endif // _COMMANDCODES_H
