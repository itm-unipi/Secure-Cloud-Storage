CC = g++
LFLAGS = -Wall -pthread -lssl -lcrypto -std=c++17 -Wno-unknown-pragmas 
CFLAGS = -Wall -c -Wno-unknown-pragmas 

all: main

main: main.o AesCbcCipherBox.o
	$(CC) -o bin/main bin/main.o bin/AesCbcCipherBox.o $(LFLAGS)

fileManagerTest: fileManagerTest.o FileManager.o
	$(CC) -o bin/fileManagerTest bin/fileManagerTest.o bin/FileManager.o $(LFLAGS)

main.o:
	$(CC) -o bin/main.o src/main.cpp $(CFLAGS)

fileManagerTest.o:
	$(CC) -o bin/fileManagerTest.o test/FileManagerTest.cpp $(CFLAGS)

AesCbcCipherBox.o:
	$(CC) -o bin/AesCbcCipherBox.o src/AesCbcCipherBox.cpp $(CFLAGS)

FileManager.o:
	$(CC) -o bin/FileManager.o src/FileManager.cpp $(CFLAGS)

clean:
	rm bin/*