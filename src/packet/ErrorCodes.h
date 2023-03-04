#ifndef _ERRORCODES_H
#define _ERRORCODES_H

#include <string>
#include <cstdint>
using namespace std;

#define NO_ERROR                  0
#define FILE_NOT_FOUND_ERROR      1
#define FILE_ALREADY_EXISTS_ERROR 2
#define RENAME_FAILED_ERROR       3
#define DELETE_FAILED_ERROR       4

string printErrorCodeDescription(uint8_t code) {

    switch (code) {

        case NO_ERROR:
            return "NO_ERROR";
    
        case FILE_NOT_FOUND_ERROR:
            return "FILE_NOT_FOUND";

        case FILE_ALREADY_EXISTS_ERROR:
            return "FILE_ALREADY_EXISTS";

        case RENAME_FAILED_ERROR:
            return "RENAME_FAILED";
        
        case DELETE_FAILED_ERROR:
            return "DELETE_FAILED_ERROR";

        default:
            return "UNKNOWN_ERROR";
    }
}

#endif // _ERRORCODES_H
