#include <openssl/pem.h>
#include <openssl/evp.h>
#include <fstream>
#include <filesystem>

#include "Worker.h"
#include "../packet/Generic.h"
#include "../packet/Login.h"
#include "../packet/Logout.h"
#include "../packet/List.h"
#include "../packet/Result.h"
#include "../security/DiffieHellman.h"
#include "../security/Sha512.h"
#include "../security/DigitalSignature.h"
#include "../security/AesCbc.h"

Worker::Worker(CommunicationSocket* socket, bool verbose) {
    m_socket = socket;
    m_verbose = verbose;

    cout << "[+] (Server) Instantiated new worker" << endl;
}

Worker::~Worker() {
    delete m_socket;

    cout << "[+] (Server) Worker closed" << endl;
}

int Worker::loginRequest() {

    // 1.) receive ephemeral key and username
    uint8_t* serialized_packet = new uint8_t[LoginM1::getSize()];
    int res = m_socket->receive(serialized_packet, LoginM1::getSize());
    if (res < 0) {
        // TODO: errore + delete
        delete[] serialized_packet;
        return -1;
    }

    LOG("(LoginRequest) Received ephemeral key and username from the client");

    // deserialize packet and get the client ephemeral key
    LoginM1 m1 = LoginM1::deserialize(serialized_packet);
    delete[] serialized_packet;

    // prepare the M2 packet
    LoginM2 m2(1);

    // check if username exists (the server must have a file called username), and retrieve the user's public key
    string filename = "resources/public_keys/" + (string)m1.username + "_key.pem";
    BIO *bp = BIO_new_file(filename.c_str(), "r");
    EVP_PKEY* user_public_key = nullptr;
    if (!bp)
        m2.result = 0;
    else{
        m_username = (string)m1.username;
        user_public_key = PEM_read_bio_PUBKEY(bp, NULL, NULL, NULL);
    }
    BIO_free(bp);

    // 2.) send the result of existence of the user
    serialized_packet = m2.serialize(); 
    res = m_socket->send(serialized_packet, LoginM2::getSize());
    delete[] serialized_packet;
    if (res < 0) {
        // TODO: errore + delete
        EVP_PKEY_free(user_public_key);
        return -2;
    }

    LOG("(LoginRequest) Send the username check result to the client");

    // if user not exists stop the worker
    if (!m2.result) {
        EVP_PKEY_free(user_public_key);
        return -3;
    }

    // extract the server private key
    filename = "resources/private_keys/server_key.pem";
    bp = BIO_new_file(filename.c_str(), "r");
    if (!bp) {
        // TODO: errore + delete
        return -4;
    }
    EVP_PKEY* private_key = PEM_read_bio_PrivateKey(bp, NULL, NULL, NULL);
    BIO_free(bp); 
    if (!private_key) {
        // TODO: errore + delete
        EVP_PKEY_free(user_public_key);
        return -5;
    }

    // generate the ephemeral_key (that contains private and public keys)
    DiffieHellman dh;
    EVP_PKEY* ephemeral_key = dh.generateEphemeralKey();

    // retrieve the peer ephemeral key from the M1 packet
    EVP_PKEY* peer_ephemeral_key = DiffieHellman::deserializeKey(m1.ephemeral_key, m1.ephemeral_key_size);

    // generate the shared secret
    uint8_t* shared_secret = nullptr;
    size_t shared_secret_size;
    res = dh.generateSharedSecret(ephemeral_key, peer_ephemeral_key, shared_secret, shared_secret_size);
    EVP_PKEY_free(peer_ephemeral_key);
    if (res < 0) {
        #pragma optimize("", off)
        memset(shared_secret, 0, shared_secret_size);
        #pragma optimize("", on)
        delete[] shared_secret;
        EVP_PKEY_free(ephemeral_key);
        EVP_PKEY_free(private_key);
        EVP_PKEY_free(user_public_key);
        return -6;
    }
    
    // generate the session key and hmac key
    unsigned char* keys = nullptr;
    unsigned int keys_size;
    Sha512::generate(shared_secret, shared_secret_size, keys, keys_size);
    memcpy(m_session_key, keys, 32 * sizeof(unsigned char));
    memcpy(m_hmac_key, keys + (32 * sizeof(unsigned char)), 32 * sizeof(unsigned char));
    #pragma optimize("", off)
    memset(shared_secret, 0, shared_secret_size);
    #pragma optimize("", on)
    delete[] shared_secret;
    delete[] keys;

    LOG("(LoginRequest) Generated session key and HMAC key");

    // load certificate from PEM
    string certificate_filename = "resources/certificates/Server_certificate.pem";
    CertificateStore* certificate_store = CertificateStore::getStore();
    X509* certificate = certificate_store->load(certificate_filename);

    // serialize certificate
    uint8_t* serialized_certificate = nullptr;
    int serialized_certificate_size = 0;
    CertificateStore::serializeCertificate(certificate, serialized_certificate, serialized_certificate_size);
    X509_free(certificate);
    
    // serialize ephemeral key
    uint8_t* serialized_ephemeral_key = nullptr;
    int serialized_ephemeral_key_size;
    res = DiffieHellman::serializeKey(ephemeral_key, serialized_ephemeral_key, serialized_ephemeral_key_size);
    EVP_PKEY_free(ephemeral_key);
    if (res < 0) {
        // TODO: errore + delete
        EVP_PKEY_free(private_key);
        delete[] serialized_certificate;
        delete[] serialized_ephemeral_key;
        EVP_PKEY_free(user_public_key);
        return -7;
    }

    // prepare <g^a,g^b>
    int ephemeral_keys_buffer_size = m1.ephemeral_key_size + serialized_ephemeral_key_size;
    uint8_t* ephemeral_keys_buffer = new uint8_t[ephemeral_keys_buffer_size];
    memcpy(ephemeral_keys_buffer, m1.ephemeral_key, m1.ephemeral_key_size);
    memcpy(ephemeral_keys_buffer + m1.ephemeral_key_size, serialized_ephemeral_key, serialized_ephemeral_key_size);

    // calculate <g^a,g^b>_s
    unsigned char* signature = nullptr;
    unsigned int signature_size;
    DigitalSignature::generate(ephemeral_keys_buffer, ephemeral_keys_buffer_size, signature, signature_size, private_key);
    EVP_PKEY_free(private_key);

    // calculate {<g^a,g^b>_s}_Ksess
    unsigned char* ciphertext = nullptr;
    unsigned char* iv = nullptr;
    int ciphertext_size = 0;
    AesCbc* encryptor = new AesCbc(ENCRYPT, m_session_key);
    encryptor->run(signature, signature_size, ciphertext, ciphertext_size, iv);
    delete[] signature;
    delete encryptor;
    
    // 3.) prepare and send the M3 packet
    LoginM3 m3(serialized_ephemeral_key, serialized_ephemeral_key_size, iv, ciphertext, serialized_certificate, serialized_certificate_size);
    serialized_packet = m3.serialize();
    res = m_socket->send(serialized_packet, LoginM3::getSize());
    delete[] serialized_packet;
    delete[] serialized_certificate;
    delete[] serialized_ephemeral_key;
    delete[] ciphertext;
    delete[] iv;
    if (res < 0) {
        // TODO: errore + delete
        EVP_PKEY_free(user_public_key);
        delete[] ephemeral_keys_buffer;
        return -8;
    }

    LOG("(LoginRequest) Sent ephemeral key, signature and certificate to the client");

    // 4.) receive the M4 packet
    serialized_packet = new uint8_t[LoginM4::getSize()];
    res = m_socket->receive(serialized_packet, LoginM4::getSize());
    if (res < 0) {
        // TODO: errore + delete
        delete[] serialized_packet;
        EVP_PKEY_free(user_public_key);
        delete[] ephemeral_keys_buffer;
        return -9;
    }

    LOG("(LoginRequest) Received signature from the client");

    // deserialize the M4 packet
    LoginM4 m4 = LoginM4::deserialize(serialized_packet);
    delete[] serialized_packet;

    // decrypt the encrypted digital signature
    unsigned char* decrypted_signature = nullptr;
    int decrypted_signature_size = 0;
    AesCbc* decryptor = new AesCbc(DECRYPT, m_session_key);
    iv = m4.iv;
    decryptor->run(m4.encrypted_signature, 144 * sizeof(uint8_t), decrypted_signature, decrypted_signature_size, iv);
    delete decryptor;

    // verify the signature
    bool signature_verification = DigitalSignature::verify(ephemeral_keys_buffer, ephemeral_keys_buffer_size, decrypted_signature, decrypted_signature_size, user_public_key);
    EVP_PKEY_free(user_public_key);
    delete[] ephemeral_keys_buffer;
    delete[] decrypted_signature;
    if (!signature_verification) {
        cerr << "[-] (LoginRequest) Invalid signature" << endl;
        return -10;
    }

    LOG("(LoginRequest) Verified client signature");

    // reset the counter
    m_counter = 0;
    return 0;
}

int Worker::logoutRequest(uint8_t* plaintext) {

    // deserialize the packet
    LogoutM1 m1 = LogoutM1::deserialize(plaintext);
    // m1.print();
    #pragma optimize("", off)
    memset(plaintext, 0, COMMAND_FIELD_PACKET_SIZE);
    #pragma optimize("", on)
    delete[] plaintext;

    // check if the counter is correct
    if (m1.counter != m_counter) {
        // TODO: use the goto?
        cerr << "[-] (LogoutRequest) Invalid counter" << endl;
    }

    incrementCounter();

    // create the result packet
    Result m2(m_counter, true);
    // m2.print();
    uint8_t* serialized_packet = m2.serialize();

    // create generic packet
    Generic generic_m2(m_session_key, m_hmac_key, serialized_packet, Result::getSize());
    #pragma optimize("", off)
    memset(serialized_packet, 0, Result::getSize());
    #pragma optimize("", on)
    delete[] serialized_packet;
    // generic_m2.print();

    // 2.) send generic packet
    serialized_packet = generic_m2.serialize();
    int res = m_socket->send(serialized_packet, Generic::getSize(Result::getSize()));
    delete[] serialized_packet;
    if (res < 0) {
        return -1;
    }

    LOG("(LogoutRequest) Sent result packet");

    // delete session key and hmac key
    #pragma optimize("", off)
    memset(m_session_key, 0, sizeof(m_session_key));
    memset(m_hmac_key, 0, sizeof(m_hmac_key));
    #pragma optimize("", on)

    LOG("(LogoutRequest) Deleted session key and HMAC key");

    return 0;
}

// ----------- BIAGIO -------------
// --------------------------------

// ----------- MATTEO -------------
// --------------------------------

// ---------- GIANLUCA ------------

int Worker::listRequest(uint8_t* plaintext){

    // deserialize the packet
    ListM1 m1 = ListM1::deserialize(plaintext);
    m1.print();
    #pragma optimize("", off)
    memset(plaintext, 0, COMMAND_FIELD_PACKET_SIZE);
    #pragma optimize("", on)
    delete[] plaintext;

    // check if the counter is correct
    if (m1.counter != m_counter) {
        // TODO: use the goto?
        cerr << "[-] (ListRequest) Invalid counter" << endl;
        return -1;
    }

    incrementCounter();

    // get file names of the
    string files = "";
    string path = "data/" + m_username;
    filesystem::directory_entry dir(path);

    if (dir.is_directory()){
        for (const auto& file : filesystem::directory_iterator(path)){

            ifstream input(file.path());
            if (input.is_open()){
                // get file name
                string file_name = file.path();
                file_name.replace(0, path.length() + 1, "");
                files = files + file_name + "|";
                input.close();
            }
        }
        
        if(files.length() > 0)
            files.replace(files.length() - 1, 1, "");
    }
    else{
        cerr << "[-] Invalid Directory" << endl;
        return -2;
    }

    uint32_t file_list_size = 0;
    uint8_t* available_files = nullptr;

    if(files.length() > 0){

        file_list_size = files.length() + 1;
        available_files = new uint8_t[file_list_size];
        memcpy(available_files, files.c_str(), file_list_size);
    }

    LOG("(ListRequest) got file names of the user");

    // create the m2 packet
    ListM2 m2(m_counter, file_list_size);
    m2.print();
    uint8_t* serialized_packet = m2.serialize();

    // create generic packet
    Generic generic_m2(m_session_key, m_hmac_key, serialized_packet, ListM2::getSize());
    #pragma optimize("", off)
    memset(serialized_packet, 0, ListM2::getSize());
    #pragma optimize("", on)
    delete[] serialized_packet;
    generic_m2.print();

    // 2.) send generic packet
    serialized_packet = generic_m2.serialize();
    int res = m_socket->send(serialized_packet, Generic::getSize(ListM2::getSize()));
    delete[] serialized_packet;
    if (res < 0) {
        return -3;
    }

    LOG("(ListRequest) Sent M2 packet");

    incrementCounter();

    // create the m3 packet
    ListM3 m3(m_counter, available_files, file_list_size);
    delete[] available_files;
    m3.print();
    serialized_packet = m3.serialize();

    // create generic packet
    Generic generic_m3(m_session_key, m_hmac_key, serialized_packet, ListM3::getSize(file_list_size));
    #pragma optimize("", off)
    memset(serialized_packet, 0, ListM3::getSize(file_list_size));
    #pragma optimize("", on)
    delete[] serialized_packet;
    generic_m3.print();

    // 2.) send generic packet
    serialized_packet = generic_m3.serialize();
    res = m_socket->send(serialized_packet, Generic::getSize(ListM3::getSize(file_list_size)));
    delete[] serialized_packet;
    if (res < 0) {
        return -4;
    }

    LOG("(ListRequest) Sent M3 packet");


    incrementCounter();
    
    return 0;

}
// --------------------------------


bool Worker::incrementCounter() {

    // check if renegotiation is needed
    if (m_counter == MAX_COUNTER_VALUE) {
        int res = loginRequest();
        if (res != 0)
            return false;
        m_counter = 0;
    } else {
        m_counter++;
    }

    return true;
}

int Worker::run() {

    int res = loginRequest();
    if (res != 0) {
        cerr << "[-] (LoginRequest) Failed with error code " << res << endl;
        return -1;
    }

    while (1) {

        // 1.) receive the generic packet
        uint8_t* serialized_packet = new uint8_t[Generic::getSize(COMMAND_FIELD_PACKET_SIZE)];
        int res = m_socket->receive(serialized_packet, Generic::getSize(COMMAND_FIELD_PACKET_SIZE));
        if (res < 0) {
            // TODO: errore + delete
            delete[] serialized_packet;
            return -1;
        }

        // deserialize the generic packet and verify the fingerprint
        Generic generic_m1 = Generic::deserialize(serialized_packet, Generic::getSize(COMMAND_FIELD_PACKET_SIZE));
        delete[] serialized_packet;
        // generic_m1.print();
        bool verification_res = generic_m1.verifyHMAC(m_hmac_key);
        if (!verification_res) {
            cerr << "[-] (Run) HMAC verification failed" << endl;
            return -2;
        }

        LOG("(Run) Received valid packet");

        // parse the command
        uint8_t* plaintext = nullptr;
        int plaintext_size = 0;
        uint8_t command_code = generic_m1.decryptCiphertext(m_session_key, plaintext, plaintext_size);

        LOG("(Run) Command received: " << printCommandCodeDescription(command_code));

        switch (command_code)
        {
            case FILE_LIST_REQ:
                listRequest(plaintext);
                break;
            case LOGOUT_REQ:
                logoutRequest(plaintext);
                return 0;
            
            default:
                cerr << "[-] (Run) Invalid command received" << endl;
                break;
        }

    }

    return 0;
}