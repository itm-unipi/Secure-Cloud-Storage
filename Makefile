CC = g++
LFLAGS = -Wall -pthread -lssl -lcrypto -std=c++17 -Wno-unknown-pragmas 
CFLAGS = -Wall -c -Wno-unknown-pragmas 

all: main

main: main.o AesCbcCipherBox.o
	$(CC) -o bin/main bin/main.o bin/AesCbcCipherBox.o $(LFLAGS)

main.o:
	$(CC) -o bin/main.o src/main.cpp $(CFLAGS)

AesCbcCipherBox.o:
	$(CC) -o bin/AesCbcCipherBox.o src/AesCbcCipherBox.cpp $(CFLAGS)

clean:
	rm bin/*