#include <openssl/pem.h>
#include <openssl/evp.h>

#include "Worker.h"
#include "../packet/Login.h"
#include "../security/DiffieHellman.h"
#include "../security/Sha512.h"

Worker::Worker(CommunicationSocket* socket) {
    m_socket = socket;
}

Worker::~Worker() {
    delete m_socket;
}

int Worker::loginRequest() {

    // 1.) receive ephemeral key and username
    uint8_t* serialized_packet = new uint8_t[LoginM1::getSize()];
    int res = m_socket->receive(serialized_packet, LoginM1::getSize());
    if (!res) {
        // TODO: errore + delete
    }

    // deserialize packet and get the client ephemeral key
    LoginM1 m1 = LoginM1::deserialize(serialized_packet);
    delete[] serialized_packet;

    // prepare the M2 packet
    LoginM2 m2(1);

    // check if username exists (the server must have a file called username)
    string filename = "resources/public_keys/" + (string)m1.username + "_key.pem";
    BIO *bp = BIO_new_file(filename.c_str(), "r");
    if (!bp)
        m2.result = 0;

    // 2.) send the result of existence of the user
    serialized_packet = m2.serialize();
    res = m_socket->send(serialized_packet, LoginM2::getSize());
    delete[] serialized_packet;
    if (!res) {
        // TODO: errore + delete
    }

    // if user not exists stop the worker
    if (!m2.result)
        return -2;

    // extract the server private key
    filename = "resources/private_keys/server_key.pem";
    bp = BIO_new_file(filename.c_str(), "r");
    if (!bp) {
        // TODO: errore + delete
    }
    EVP_PKEY* private_key = PEM_read_bio_PrivateKey(bp, NULL, NULL, NULL);
    if (!private_key) {
        // TODO: errore + delete
    }
    BIO_free(bp); 

    // generate the ephemeral_key (that contains private and public keys)
    DiffieHellman dh;
    EVP_PKEY* ephemeral_key = dh.generateEphemeralKey();

    // retrieve the peer ephemeral key from the M1 packet
    EVP_PKEY* peer_ephemeral_key = DiffieHellman::deserializeKey(m1.ephemeral_key, m1.ephemeral_key_size);

    // generate the shared secret
    uint8_t* shared_secret = nullptr;
    size_t shared_secret_size;
    res = dh.generateSharedSecret(ephemeral_key, peer_ephemeral_key, shared_secret, shared_secret_size);
    if (res) {
        // TODO: errore + delete
    }
    
    // generate the session key and hmac key
    unsigned char* keys;
    unsigned int keys_size;
    Sha512::generate(shared_secret, shared_secret_size, keys, keys_size);
    memcpy(m_session_key, keys, 16 * sizeof(unsigned char));
    memcpy(m_hmac_key, keys + (16 * sizeof(unsigned char)), 16 * sizeof(unsigned char));
    cout << "SESSION KEY: " << m_session_key << endl;
    cout << "HMAC KEY: " << m_hmac_key << endl;

    return 0;
}

int Worker::logoutRequest() {
    return 0;
}

int Worker::run() {

    loginRequest();
    return 0;
}