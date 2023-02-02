CC = g++
LFLAGS = -Wall -pthread -lssl -lcrypto -std=c++17 -Wno-unknown-pragmas -Wno-deprecated-declarations
CFLAGS = -Wall -c -Wno-unknown-pragmas -Wno-deprecated-declarations

all: 

aesCbcTest: AesCbc.o
	$(CC) -o bin/aesCbcTest bin/AesCbc.o test/AesCbcTest.cpp $(LFLAGS)

fileManagerTest:  FileManager.o AesCbc.o
	$(CC) -o bin/fileManagerTest bin/FileManager.o bin/AesCbc.o test/FileManagerTest.cpp $(LFLAGS)

sha512test: Sha512.o
	$(CC) -o bin/sha512test bin/Sha512.o test/Sha512Test.cpp $(LFLAGS)

hmactest: Hmac.o
	$(CC) -o bin/hmactest bin/Hmac.o test/HmacTest.cpp $(LFLAGS)

signatureTest: DigitalSignature.o
	$(CC) -o bin/signatureTest bin/DigitalSignature.o test/DigitalSignatureTest.cpp $(LFLAGS)

AesCbc.o:
	$(CC) -o bin/AesCbc.o src/AesCbc.cpp $(CFLAGS)

FileManager.o:
	$(CC) -o bin/FileManager.o src/FileManager.cpp $(CFLAGS)

Sha512.o:
	$(CC) -o bin/Sha512.o src/Sha512.cpp $(CFLAGS)

Hmac.o:
	$(CC) -o bin/Hmac.o src/Hmac.cpp $(CFLAGS)

DigitalSignature.o:
	$(CC) -o bin/DigitalSignature.o src/DigitalSignature.cpp $(CFLAGS)

clean:
	rm bin/*