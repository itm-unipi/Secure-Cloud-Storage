# Prototipo OpenSSL

Per compilare a mano su winzoz:

```bash
// prototipo
g++ -o bin/main src/AesCbcCipherBox.cpp src/main.cpp -Wall -pthread -L/usr/local/lib -lssl -lcrypto -I/usr/local/include -std=c++17 -Wno-unknown-pragmas

// encryptor prof
g++ -o bin/encryptor src/encryptor.cpp -Wall -pthread -L/usr/local/lib -lssl -lcrypto -I/usr/local/include -std=c++17 -Wno-unknown-pragmas

// decryptor prof
g++ -o bin/decryptor src/decryptor.cpp -Wall -pthread -L/usr/local/lib -lssl -lcrypto -I/usr/local/include -std=c++17 -Wno-unknown-pragmas
```

Su linux:

```bash
make
```