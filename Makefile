CC = g++
LFLAGS = -Wall -pthread -lssl -lcrypto -lstdc++fs -std=c++17 -Wno-unknown-pragmas -Wno-deprecated-declarations
CFLAGS = -Wall -c -std=c++17 -Wno-unknown-pragmas -Wno-deprecated-declarations

all: server client

server: Server.o Socket.o DiffieHellman.o Sha512.o CertificateStore.o DigitalSignature.o AesCbc.o Hmac.o FileManager.o
	$(CC) -o bin/server bin/Server.o bin/Worker.o bin/ListeningSocket.o bin/CommunicationSocket.o bin/DiffieHellman.o bin/Sha512.o bin/CertificateStore.o bin/DigitalSignature.o bin/AesCbc.o bin/Hmac.o bin/FileManager.o src/server/Main.cpp $(LFLAGS)

client: Client.o Socket.o DiffieHellman.o Sha512.o CertificateStore.o DigitalSignature.o AesCbc.o Hmac.o FileManager.o
	$(CC) -o bin/client bin/Client.o bin/CommunicationSocket.o bin/DiffieHellman.o bin/Sha512.o bin/CertificateStore.o bin/DigitalSignature.o bin/AesCbc.o bin/Hmac.o bin/FileManager.o src/client/Main.cpp $(LFLAGS)

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

encryptPrivateKey:
	$(CC) -o bin/encryptPrivateKey test/EncryptPrivateKey.cpp $(LFLAGS)

extractPublicKey: CertificateStore.o
	$(CC) -o bin/extractPublicKey bin/CertificateStore.o test/ExtractPublicKey.cpp $(LFLAGS)

Server.o:
	$(CC) -o bin/Server.o src/server/Server.cpp $(CFLAGS)
	$(CC) -o bin/Worker.o src/server/Worker.cpp $(CFLAGS)

Client.o:
	$(CC) -o bin/Client.o src/client/Client.cpp $(CFLAGS)

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