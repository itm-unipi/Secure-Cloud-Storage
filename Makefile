CC = g++
LFLAGS = -Wall -pthread -lssl -lcrypto -std=c++17 -Wno-unknown-pragmas -Wno-deprecated-declarations
CFLAGS = -Wall -c -Wno-unknown-pragmas -Wno-deprecated-declarations

all: main

main: main.o AesCbcCipherBox.o
	$(CC) -o bin/main bin/main.o bin/AesCbcCipherBox.o $(LFLAGS)

fileManagerTest:  FileManager.o AesCbcCipherBox.o
	$(CC) -o bin/fileManagerTest bin/FileManager.o bin/AesCbcCipherBox.o test/FileManagerTest.cpp $(LFLAGS)

sha512test: Sha512.o
	$(CC) -o bin/sha512test bin/Sha512.o test/Sha512Test.cpp $(LFLAGS)

hmactest: Hmac.o
	$(CC) -o bin/hmactest bin/Hmac.o test/HmacTest.cpp $(LFLAGS)

main.o:
	$(CC) -o bin/main.o src/main.cpp $(CFLAGS)

AesCbcCipherBox.o:
	$(CC) -o bin/AesCbcCipherBox.o src/AesCbcCipherBox.cpp $(CFLAGS)

FileManager.o:
	$(CC) -o bin/FileManager.o src/FileManager.cpp $(CFLAGS)

Sha512.o:
	$(CC) -o bin/Sha512.o src/Sha512.cpp $(CFLAGS)

Hmac.o:
	$(CC) -o bin/Hmac.o src/Hmac.cpp $(CFLAGS)

clean:
	rm bin/*