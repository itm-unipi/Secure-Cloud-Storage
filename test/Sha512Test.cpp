#include <iostream>
#include "../src/Sha512.h"
using namespace std;

int main() {

    unsigned char msg[] = "Lorem ipsum dolor sit amet.";

    unsigned char* digest = nullptr;
    unsigned int digest_size = 0;
    Sha512::generate(msg, sizeof(msg), digest, digest_size);

    if (Sha512::verify(msg, sizeof(msg), digest, digest_size))
        cout << "HASH uguali" << endl;
    else
        cerr << "HASH diversi" << endl;

    return 0;
}