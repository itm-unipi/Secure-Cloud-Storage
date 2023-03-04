#ifndef _CONFIG_H
#define _CONFIG_H

#define SERVER_IP "localhost"
#define SERVER_PORT 6000
#define MAX_QUEUE 10
#define USERNAME_SIZE 30
#define COMMAND_FIELD_PACKET_SIZE 65 * sizeof(uint8_t)          // the longest command packet is the Rename Command (65 byte)
#define MAX_COUNTER_VALUE 0xffffffff
#define CHUNK_SIZE 64 * 1024
#define FILE_NAME_SIZE 30

#endif  // _CONFIG_H
