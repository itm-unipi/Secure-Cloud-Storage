CC = g++
LFLAGS = -Wall -pthread -lssl -lcrypto -std=c++17 -Wno-unknown-pragmas -Wno-deprecated-declarations
CFLAGS = -Wall -c -Wno-unknown-pragmas -Wno-deprecated-declarations

all: 

test: aesCbcTest fileManagerTest sha512test hmacTest signatureTest certificateTest diffieHellmanTest socketTest

aesCbcTest: AesCbc.o
	$(CC) -o bin/aesCbcTest bin/AesCbc.o test/AesCbcTest.cpp $(LFLAGS)

fileManagerTest:  FileManager.o AesCbc.o
	$(CC) -o bin/fileManagerTest bin/FileManager.o bin/AesCbc.o test/FileManagerTest.cpp $(LFLAGS)

sha512test: Sha512.o
	$(CC) -o bin/sha512test bin/Sha512.o test/Sha512Test.cpp $(LFLAGS)

hmacTest: Hmac.o
	$(CC) -o bin/hmactest bin/Hmac.o test/HmacTest.cpp $(LFLAGS)

signatureTest: DigitalSignature.o
	$(CC) -o bin/signatureTest bin/DigitalSignature.o test/DigitalSignatureTest.cpp $(LFLAGS)

certificateTest: CertificateStore.o
	$(CC) -o bin/certificateTest bin/CertificateStore.o test/CertificateStoreTest.cpp $(LFLAGS)

diffieHellmanTest: DiffieHellman.o Sha512.o
	$(CC) -o bin/diffieHellmanTest bin/DiffieHellman.o bin/Sha512.o test/DiffieHellmanTest.cpp $(LFLAGS)

socketTest: Socket.o
	$(CC) -o bin/socketTest bin/ListeningSocket.o bin/CommunicationSocket.o test/SocketTest.cpp $(LFLAGS)

AesCbc.o:
	$(CC) -o bin/AesCbc.o src/security/AesCbc.cpp $(CFLAGS)

FileManager.o:
	$(CC) -o bin/FileManager.o src/utility/FileManager.cpp $(CFLAGS)

Sha512.o:
	$(CC) -o bin/Sha512.o src/security/Sha512.cpp $(CFLAGS)

Hmac.o:
	$(CC) -o bin/Hmac.o src/security/Hmac.cpp $(CFLAGS)

DigitalSignature.o:
	$(CC) -o bin/DigitalSignature.o src/security/DigitalSignature.cpp $(CFLAGS)

CertificateStore.o:
	$(CC) -o bin/CertificateStore.o src/security/CertificateStore.cpp $(CFLAGS)

DiffieHellman.o:
	$(CC) -o bin/DiffieHellman.o src/security/DiffieHellman.cpp $(CFLAGS)

Socket.o:
	$(CC) -o bin/ListeningSocket.o src/utility/ListeningSocket.cpp $(CFLAGS)
	$(CC) -o bin/CommunicationSocket.o src/utility/CommunicationSocket.cpp $(CFLAGS)

clean:
	rm bin/*