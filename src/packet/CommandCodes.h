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

string printCommandCodeDescription(uint8_t code) {

    switch (code){

        case REQ_FAILED:
            return "REQ_FAILED";

        case REQ_SUCCESS:
            return "REQ_SUCCESS";
        
        case UPLOAD_REQ:
            return "UPLOAD_REQ";
        
        case FILE_CHUNK:
            return "FILE_CHUNK";
        
        case TRANSFER_ACK:
            return "TRANSFER_ACK";

        case DOWNLOAD_REQ:
            return "DOWNLOAD_REQ";

        case FILE_FOUND:
            return "FILE_FOUND";

        case FILE_NOT_FOUND:
            return "FILE_NOT_FOUND";        

        case DELETE_REQ:
            return "DELETE_REQ";

        case FILE_LIST_REQ:
            return "FILE_LIST_REQ";
        
        case FILE_LIST_SIZE:
            return "FILE_LIST_SIZE";

        case FILE_LIST:
            return "FILE_LIST";
        
        case RENAME_REQ:
            return "RENAME_REQ";

        case LOGOUT_REQ:
            return "LOGOUT_REQ";
    
        default:
            return "UNKNOWN";
    }
}

#endif // _COMMANDCODES_H
