#include <openssl/pem.h>
#include <openssl/evp.h>

#include "Worker.h"
#include "../packet/Login.h"
#include "../security/DiffieHellman.h"
#include "../security/Sha512.h"
#include "../security/DigitalSignature.h"
#include "../security/AesCbc.h"

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
    memcpy(m_session_key, keys, 32 * sizeof(unsigned char));
    memcpy(m_hmac_key, keys + (32 * sizeof(unsigned char)), 32 * sizeof(unsigned char));

    // load certificate from PEM
    string certificate_filename = "resources/certificates/Server_certificate.pem";
    CertificateStore* certificate_store = CertificateStore::getStore();
    X509* certificate = certificate_store->load(certificate_filename);

    // serialize certificate
    uint8_t* serialized_certificate = nullptr;
    int serialized_certificate_size = 0;
    CertificateStore::serializeCertificate(certificate, serialized_certificate, serialized_certificate_size);
    
    // serialize ephemeral key
    uint8_t* serialized_ephemeral_key = nullptr;
    int serialized_ephemeral_key_size;
    res = DiffieHellman::serializeKey(ephemeral_key, serialized_ephemeral_key, serialized_ephemeral_key_size);
    if (!res) {
        // TODO: errore + delete
    }

    // prepare <g^a,g^b>
    uint8_t* ephemeral_keys_buffer = new uint8_t[m1.ephemeral_key_size + serialized_ephemeral_key_size];
    memcpy(ephemeral_keys_buffer, m1.ephemeral_key, m1.ephemeral_key_size);
    memcpy(ephemeral_keys_buffer + m1.ephemeral_key_size, serialized_ephemeral_key, serialized_ephemeral_key_size);

    // calculate <g^a,g^b>_s
    unsigned char* signature;
    unsigned int signature_size;
    DigitalSignature::generate(ephemeral_keys_buffer, m1.ephemeral_key_size + serialized_ephemeral_key_size, signature, signature_size, private_key);

    // calculate {<g^a,g^b>_s}_Ksess
    unsigned char* ciphertext = nullptr;
    unsigned char* iv = nullptr;
    int ciphertext_size = 0;
    AesCbc* encryptor = new AesCbc(ENCRYPT, m_session_key);
    encryptor->run(signature, signature_size, ciphertext, ciphertext_size, iv);
    
    // 3) prepare and send the M3 packet
    LoginM3 m3(serialized_ephemeral_key, serialized_ephemeral_key_size, iv, ciphertext, serialized_certificate, serialized_certificate_size);
    serialized_packet = m3.serialize();

    res = m_socket->send(serialized_packet, LoginM3::getSize());
    delete[] serialized_packet;
    if (!res) {
        // TODO: errore + delete
    }

    cout << "SHARED SECRET: ";
    for (int i = 0; i < 256; ++i)
        cout << shared_secret[i];
    cout << endl;

    cout << "SESSION KEY: ";
    for (int i = 0; i < 32; ++i)
        cout << m_session_key[i];
    cout << endl;

    cout << "HMAC KEY: ";
    for (int i = 0; i < 32; ++i)
        cout << m_hmac_key[i];
    cout << endl;

    return 0;
}

int Worker::logoutRequest() {
    return 0;
}

int Worker::run() {

    loginRequest();
    return 0;
}