#include <openssl/pem.h>
#include <openssl/bio.h>
#include <iostream>
#include <cstring>

using namespace std;

int main() {

    string pem_files[] = { "biagio_key.pem", "gianluca_key.pem", "matteo_key.pem" };
    string passwords[] = { "biagio", "gianluca", "matteo" };

    for (int i = 0; i < 3; ++i) {

        // read private key in clear from pem file
        string filepath = "resources/private_keys/" + pem_files[i];
        BIO *bio = BIO_new_file(filepath.c_str(), "r");
        EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);

        // prepare AES encryption
        const char* password = passwords[i].c_str();
        const int password_size = strlen(password);
        const EVP_CIPHER *cipher = EVP_aes_256_cbc();

        // save the encrypted key
        string new_filepath2 = "resources/encrypted_keys/" + pem_files[i];
        BIO *bio2 = BIO_new_file(new_filepath2.c_str(), "w");
        PEM_write_bio_PrivateKey(bio2, pkey, cipher, (unsigned char*)password, password_size, 0, 0);

        BIO_free(bio);
    }

    return 0;
}
