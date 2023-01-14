CC = g++
LFLAGS = -Wall -pthread -lssl -lcrypto -std=c++17 -Wno-unknown-pragmas 
CFLAGS = -Wall -c

all: main

main: main.o AesCbcCipherBox.o
	$(CC) -o bin/main $(LFLAGS) bin/main.o bin/AesCbcCipherBox.o
	# g++ -o bin/main bin/main.o bin/AesCbcCipherBox.o -Wall -pthread -L/usr/local/lib -lssl -lcrypto -I/usr/local/include -std=c++17 -Wno-unknown-pragmas

encryptor: encryptor.o
	$(CC) -o bin/encryptor $(LFLAGS) bin/encryptor.o
	# g++ -o bin/encryptor bin/encryptor.o -Wall -pthread -L/usr/local/lib -lssl -lcrypto -I/usr/local/include -std=c++17 -Wno-unknown-pragmas

decryptor: decryptor.o
	$(CC) -o bin/decryptor $(LFLAGS) bin/decryptor.o
	# g++ -o bin/decryptor bin/decryptor.o -Wall -pthread -L/usr/local/lib -lssl -lcrypto -I/usr/local/include -std=c++17 -Wno-unknown-pragmas

encryptor.o:
	$(CC) -o bin/encryptor.o $(CFLAGS) src/encryptor.cpp

decryptor.o:
	$(CC) -o bin/decryptor.o $(CFLAGS) src/decryptor.cpp

main.o:
	$(CC) -o bin/main.o $(CFLAGS) src/main.cpp

AesCbcCipherBox.o:
	$(CC) -o bin/AesCbcCipherBox.o $(CFLAGS) src/AesCbcCipherBox.cpp

clean:
	rm bin/*