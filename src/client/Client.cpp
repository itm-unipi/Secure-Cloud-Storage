#include <iostream>
#include <cstring>
#include <openssl/pem.h>

#include "Client.h"
#include "../packet/Login.h"
#include "../security/DiffieHellman.h"
#include "../security/Sha512.h"
#include "../security/DigitalSignature.h"
#include "../security/AesCbc.h"

using namespace std;

Client::Client(bool verbose) { 
    
    this->verbose = verbose; 
    this->m_socket = nullptr;
    this->m_long_term_key = nullptr;
}

Client::~Client() {

    delete m_socket;
    EVP_PKEY_free(m_long_term_key);
    CertificateStore::deleteStore();

    // overwrite session key and hmac key
    #pragma optimize("", off)
    memset(m_session_key, 0, sizeof(m_session_key));
    memset(m_hmac_key, 0, sizeof(m_hmac_key));
    #pragma optimize("", on)
}

int Client::login() {

    // generate the ephemeral key (that contains private and public keys)
    DiffieHellman dh;
    EVP_PKEY* ephemeral_key = dh.generateEphemeralKey();

    // serialize ephemeral key
    uint8_t* serialized_ephemeral_key = nullptr;
    int serialized_ephemeral_key_size;
    int res = DiffieHellman::serializeKey(ephemeral_key, serialized_ephemeral_key, serialized_ephemeral_key_size);
    if (res < 0) {
        EVP_PKEY_free(ephemeral_key);
        delete[] serialized_ephemeral_key;
        return -1;
    }

    // 1.) send ephemeral key and username
    LoginM1 m1(serialized_ephemeral_key, serialized_ephemeral_key_size, m_username);
    uint8_t* serialized_packet = m1.serialize();
    res = m_socket->send(serialized_packet, LoginM1::getSize());
    delete[] serialized_packet;
    if (res < 0) {
        EVP_PKEY_free(ephemeral_key);
        delete[] serialized_ephemeral_key;
        return -2;
    }

    LOG("(Login) Ephemeral key and username sent to the server");

    // 2.) receive the result of existence of the user
    serialized_packet = new uint8_t[LoginM2::getSize()];
    res = m_socket->receive(serialized_packet, LoginM2::getSize());
    if (res < 0) {
        delete[] serialized_packet;
        EVP_PKEY_free(ephemeral_key);
        delete[] serialized_ephemeral_key;
        return -3;
    }

    LOG("(Login) Received username check result from the server");

    // check if the server found the username
    uint8_t result_check = LoginM2::deserialize(serialized_packet).result;
    delete[] serialized_packet;
    if (!result_check) {
        cerr << "[-] (Login) User not exists" << endl;
        EVP_PKEY_free(ephemeral_key);
        delete[] serialized_ephemeral_key;
        return -4;
    }

    // 3.) receive the M3 packet
    serialized_packet = new uint8_t[LoginM3::getSize()];
    res = m_socket->receive(serialized_packet, LoginM3::getSize());
    if (res < 0) {
        delete[] serialized_packet;
        EVP_PKEY_free(ephemeral_key);
        delete[] serialized_ephemeral_key;
        return -5;
    }

    LOG("(Login) Received ephemeral key, signature and certificate from the server");

    // deserialize the M3 packet
    LoginM3 m3 = LoginM3::deserialize(serialized_packet);
    delete[] serialized_packet;

    // retrieve the peer ephemeral key from the M3 packet
    EVP_PKEY* peer_ephemeral_key = DiffieHellman::deserializeKey(m3.ephemeral_key, m3.ephemeral_key_size);

    // generate the shared secret
    uint8_t* shared_secret = nullptr;
    size_t shared_secret_size;    
    res = dh.generateSharedSecret(ephemeral_key, peer_ephemeral_key, shared_secret, shared_secret_size);
    EVP_PKEY_free(ephemeral_key);
    EVP_PKEY_free(peer_ephemeral_key);
    if (res < 0) {
        #pragma optimize("", off)
        memset(shared_secret, 0, shared_secret_size);
        #pragma optimize("", on)
        delete[] shared_secret;
        delete[] serialized_ephemeral_key;
        return -6;
    }
    
    // generate the session key and hmac key
    unsigned char* keys;
    unsigned int keys_size;
    Sha512::generate(shared_secret, shared_secret_size, keys, keys_size);
    memcpy(m_session_key, keys, 32 * sizeof(unsigned char));
    memcpy(m_hmac_key, keys + (32 * sizeof(unsigned char)), 32 * sizeof(unsigned char));
    #pragma optimize("", off)
    memset(shared_secret, 0, shared_secret_size);
    #pragma optimize("", on)
    delete[] shared_secret;
    delete[] keys;

    LOG("(Login) Generated session key and HMAC key");
    
    // prepare <g^a,g^b>
    int ephemeral_keys_buffer_size = m3.ephemeral_key_size + serialized_ephemeral_key_size;
    uint8_t* ephemeral_keys_buffer = new uint8_t[ephemeral_keys_buffer_size];
    memcpy(ephemeral_keys_buffer, serialized_ephemeral_key, serialized_ephemeral_key_size);
    memcpy(ephemeral_keys_buffer + serialized_ephemeral_key_size, m3.ephemeral_key, m3.ephemeral_key_size);
    delete[] serialized_ephemeral_key;
    
    // calculate <g^a,g^b>_s
    unsigned char* signature;
    unsigned int signature_size;
    DigitalSignature::generate(ephemeral_keys_buffer, ephemeral_keys_buffer_size, signature, signature_size, m_long_term_key);

    // calculate {<g^a,g^b>_s}_Ksess
    unsigned char* ciphertext = nullptr;
    unsigned char* iv = nullptr;
    int ciphertext_size = 0;
    AesCbc* encryptor = new AesCbc(ENCRYPT, m_session_key);
    encryptor->run(signature, signature_size, ciphertext, ciphertext_size, iv);
    delete[] signature;
    delete encryptor;

    // retrieve and verify the certificate
    X509* server_certificate = CertificateStore::deserializeCertificate(m3.serialized_certificate, m3.serialized_certificate_size);
    CertificateStore* certificate_store = CertificateStore::getStore();
    if (!certificate_store->verify(server_certificate)) {
        X509_free(server_certificate);
        delete[] ephemeral_keys_buffer;
        delete[] ciphertext;
        delete[] iv;
        return -7;
    }

    LOG("(Login) Verified server certificate");

    // retrieve the server public key 
    EVP_PKEY* server_public_key = certificate_store->getPublicKey(server_certificate);
    X509_free(server_certificate);

    // decrypt the encrypted digital signature
    unsigned char* decrypted_signature = nullptr;
    int decrypted_signature_size = 0;
    AesCbc* decryptor = new AesCbc(DECRYPT, m_session_key);
    unsigned char* signature_iv = m3.iv; 
    decryptor->run(m3.encrypted_signature, 144 * sizeof(uint8_t), decrypted_signature, decrypted_signature_size, signature_iv);
    delete decryptor;

    // verify the signature
    bool signature_verification = DigitalSignature::verify(ephemeral_keys_buffer, ephemeral_keys_buffer_size, decrypted_signature, decrypted_signature_size, server_public_key);
    delete[] ephemeral_keys_buffer;
    delete[] decrypted_signature;
    EVP_PKEY_free(server_public_key);
    if (!signature_verification) {
        delete[] ciphertext;
        delete[] iv;
        return -8;
    }

    LOG("(Login) Verified server signature");

    // 4.) prepare and send the M4 packet
    LoginM4 m4(iv, ciphertext);
    serialized_packet = m4.serialize();
    res = m_socket->send(serialized_packet, LoginM4::getSize());
    delete[] serialized_packet;
    delete[] ciphertext;
    delete[] iv;
    if (res < 0) {
        return -9;
    }

    LOG("(Login) Sent signature to the server");

    return 0;
}

int Client::logout() {
    return 0;
}

int Client::run() {

    // --------------- INITIALIZATION ---------------

    string username, password;
    cout << "Insert username: ";
    cin >> m_username;
    cout << "Insert password: ";
    cin >> password;
    
    // sanitize username and password
    static char ok_chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-.@?!#*";
    if (strspn(m_username.c_str(), ok_chars) < strlen(m_username.c_str())) { 
        cerr << "[-] (Client) Not valid username" << endl;
        return -1;
    }
    if (strspn(password.c_str(), ok_chars) < strlen(password.c_str())) { 
        cerr << "[-] (Client) Not valid username" << endl;
        return -1;
    }
    if (m_username.length() >= 30) {
        cerr << "[-] (Client) Username too long" << endl;
        return -1;
    } 

    // open the private key PEM file
    string private_key_file = "resources/encrypted_keys/" + m_username + "_key.pem";
    BIO *bio = BIO_new_file(private_key_file.c_str(), "r");
    if (!bio) {
        cerr << "[-] (Client) Failed to open encrypted key PEM file" << endl;
        return -2;
    }
    
    // encrypt and save the long term private key
    m_long_term_key = PEM_read_bio_PrivateKey(bio, 0, 0, (void *)password.c_str());
    BIO_free(bio);

    // connect to the server
    try {
        m_socket = new CommunicationSocket(SERVER_IP, SERVER_PORT);
    } catch (const std::exception& e) {
        std::cerr << "[-] (Client) Exception: " << e.what() << std::endl;
        return -3;
    }

    // ----------------------------------------------

    int res = login();
    if (res != 0) {
        cerr << "[-] (Login) Failed with error code " << res << endl;
        return -1;
    }

    while (1) {
        
        string command;
        cout << "Insert next command: ";
        cin >> command;

        if (command == "list") {

        }

        else if (command == "download") {

        }

        else if (command == "upload") {

        }

        else if (command == "rename") {

        }

        else if (command == "delete") {

        }

        else if (command == "logout") {
            return 0;
        }
        
        else if (command == "exit") {
            return 1;
        }

        else if (command == "help") {
            cout << "----------- COMMANDS -----------" << endl;
            cout << "list: " << endl;
            cout << "download:" << endl;
            cout << "upload:" << endl;
            cout << "rename:" << endl;
            cout << "delete:" << endl;
            cout << "logout:" << endl;
            cout << "exit:" << endl;
            cout << "--------------------------------" << endl;
        }

        else {
            cerr << "[-] (Client) Not valid command" << endl;
        }
        
    }

    return 0;
}