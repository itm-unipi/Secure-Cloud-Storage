#include <iostream>
#include "../src/Hmac.h"
using namespace std;

int main() {

    unsigned char msg[] = "Lorem ipsum dolor sit amet.";
    unsigned char *key = (unsigned char *)"abcdefghijklmnopabcdefghijklmnop";
    Hmac hmac(key);

    unsigned char* digest = nullptr;
    unsigned int digest_size = 0;
    hmac.generate(msg, sizeof(msg), digest, digest_size);

    if (hmac.verify(msg, sizeof(msg), digest, digest_size))
        cout << "HMAC uguali" << endl;
    else
        cerr << "HMAC diversi" << endl;

    return 0;
}