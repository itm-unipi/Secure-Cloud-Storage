#include <iostream>
#include <cstring>
#include <cmath>
#include <filesystem>
#include <openssl/pem.h>

#include "Client.h"
#include "../packet/Generic.h"
#include "../packet/Login.h"
#include "../packet/Logout.h"
#include "../packet/List.h"
#include "../packet/Rename.h"
#include "../packet/Remove.h"
#include "../packet/Result.h"
#include "../packet/Download.h"
#include "../packet/Upload.h"
#include "../security/DiffieHellman.h"
#include "../security/Sha512.h"
#include "../security/DigitalSignature.h"
#include "../security/AesCbc.h"
#include "../utility/FileManager.h"

using namespace std;

Client::Client(bool verbose) { 
    
    m_verbose = verbose; 
    m_socket = nullptr;
    m_long_term_key = nullptr;
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

// ------------------------------------------------------------------------------

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
        cerr << "User not registered" << endl;
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
        safeDelete(shared_secret, shared_secret_size);
        delete[] serialized_ephemeral_key;
        return -6;
    }
    
    // generate the session key and hmac key
    unsigned char* keys = nullptr;
    unsigned int keys_size;
    Sha512::generate(shared_secret, shared_secret_size, keys, keys_size);
    memcpy(m_session_key, keys, AES_KEY_SIZE * sizeof(unsigned char));
    memcpy(m_hmac_key, keys + (HMAC_DIGEST_SIZE * sizeof(unsigned char)), HMAC_DIGEST_SIZE * sizeof(unsigned char));
    safeDelete(shared_secret, shared_secret_size);
    delete[] keys;

    LOG("(Login) Generated session key and HMAC key");
    
    // prepare <g^a,g^b>
    int ephemeral_keys_buffer_size = m3.ephemeral_key_size + serialized_ephemeral_key_size;
    uint8_t* ephemeral_keys_buffer = new uint8_t[ephemeral_keys_buffer_size];
    memcpy(ephemeral_keys_buffer, serialized_ephemeral_key, serialized_ephemeral_key_size);
    memcpy(ephemeral_keys_buffer + serialized_ephemeral_key_size, m3.ephemeral_key, m3.ephemeral_key_size);
    delete[] serialized_ephemeral_key;
    
    // calculate <g^a,g^b>_s
    unsigned char* signature = nullptr;
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

    // reset the counter
    m_counter = 0;
    return 0;
}

// ------------------------------------------------------------------------------

int Client::logout() {

    // create the M1 packet
    LogoutM1 m1(m_counter);
    // m1.print();
    uint8_t* serialized_packet = m1.serialize();

    // create generic packet
    Generic generic_m1(m_session_key, m_hmac_key, serialized_packet, COMMAND_FIELD_PACKET_SIZE);
    safeDelete(serialized_packet, COMMAND_FIELD_PACKET_SIZE);
    // generic_m1.print();

    // 1.) send generic packet
    serialized_packet = generic_m1.serialize();
    int res = m_socket->send(serialized_packet, Generic::getSize(COMMAND_FIELD_PACKET_SIZE));
    delete[] serialized_packet;
    if (res < 0) {
        return -1;
    }

    incrementCounter();

    // 2.) receive the generic packet
    serialized_packet = new uint8_t[Generic::getSize(Result::getSize())];
    res = m_socket->receive(serialized_packet, Generic::getSize(Result::getSize()));
    if (res < 0) {
        delete[] serialized_packet;
        return -2;
    }

    // deserialize the generic packet and verify the fingerprint
    Generic generic_m2 = Generic::deserialize(serialized_packet, Generic::getSize(Result::getSize()));
    delete[] serialized_packet;
    // generic_m2.print();
    bool verification_res = generic_m2.verifyHMAC(m_hmac_key);
    if (!verification_res) {
        LOG("(Logout) HMAC verification failed");
        return -3;
    }

    LOG("(Logout) Received valid packet");

    // get the m2 packet
    uint8_t* plaintext = nullptr;
    int plaintext_size = 0;
    generic_m2.decryptCiphertext(m_session_key, plaintext, plaintext_size);
    Result m2 = Result::deserialize(plaintext);
    // m2.print();
    safeDelete(plaintext, Result::getSize());

    // check if the counter is correct
    if (m2.counter != m_counter)
        throw -2;

    // check if operation failed
    if (m2.command_code == REQ_SUCCESS)
        return 0;
    else if (m2.command_code == REQ_FAILED)
        return -4;

    return -5;
}

// ------------------------------------------------------------------------------

int Client::download(string file_name) {

    if (FileManager::exists(file_name)) {
        cerr << "The requested file already exists in local filesystem" << endl;
        return -1;
    }

    // 1) send command packet along with the file_name to download
    DownloadM1 m1(m_counter, file_name);
    // m1.print();
    uint8_t* serialized_packet = m1.serialize();

    Generic generic_m1(m_session_key, m_hmac_key, serialized_packet, COMMAND_FIELD_PACKET_SIZE);
    safeDelete(serialized_packet, COMMAND_FIELD_PACKET_SIZE);

    serialized_packet = generic_m1.serialize();
    int res = m_socket->send(serialized_packet, Generic::getSize(COMMAND_FIELD_PACKET_SIZE));
    delete[] serialized_packet;
    if (res < 0) {
        return -2;
    }

    incrementCounter();

    // 2) receive the download M2 packet
    int generic_m2_size = Generic::getSize(DownloadM2::getSize());
    serialized_packet = new uint8_t[generic_m2_size];
    res = m_socket->receive(serialized_packet, generic_m2_size);
    if (res < 0) {
        return -3;
    }

    // deserialize the generic packet and verify the fingerprint
    Generic generic_m2 = Generic::deserialize(serialized_packet, generic_m2_size);
    delete[] serialized_packet;
    bool verification_res = generic_m2.verifyHMAC(m_hmac_key);
    if (!verification_res) {
        LOG("(Download) HMAC verification failed");
        return -4;
    }

    LOG("(Download) Received valid packet");
    
    // get the packet content
    uint8_t* plaintext = nullptr;
    int plaintext_size = 0;
    generic_m2.decryptCiphertext(m_session_key, plaintext, plaintext_size);
    DownloadM2 m2 = DownloadM2::deserialize(plaintext);
    // m2.print();
    safeDelete(plaintext, DownloadM2::getSize());

    // check if the counter is correct
    if (m2.counter != m_counter)
        throw -2;

    incrementCounter();

    // check if the requested file has been found on the cloud
    if (m2.command_code == FILE_NOT_FOUND) {
        cerr << "File not found" << endl;
        return -5;
    }

    // initialize the file manager in order to create file on the file system and obtain all the info about the requested file
    FileManager requested_file(file_name, WRITE);
    size_t file_size = m2.file_size != 0 ? m2.file_size : 4UL * 1024 * 1024 * 1024;
    requested_file.calculateFileInfo(file_size);
    
    // wait for the receipt of all file chunks
    size_t chunk_size = requested_file.getChunkSize();
    size_t received_bytes = 0;
    int new_progress, progress = -1;
    for (size_t i = 0; i < requested_file.getNumOfChunks(); i++) {
        
        if (i == requested_file.getNumOfChunks() - 1)
            chunk_size = requested_file.getLastChunkSize();

        // 3) receive the download Mi packet
        int generic_mi_size = Generic::getSize(DownloadMi::getSize(chunk_size));
        serialized_packet = new uint8_t[generic_mi_size];
        res = m_socket->receive(serialized_packet, generic_mi_size);
        if (res < 0) {
            return -6;
        }

        // deserialize the generic packet and verify the fingerprint
        Generic generic_mi = Generic::deserialize(serialized_packet, generic_mi_size);
        delete[] serialized_packet;
        bool verification_res = generic_mi.verifyHMAC(m_hmac_key);
        if (!verification_res) {
            LOG("(Download) HMAC verification failed");
            return -7;
        }
        
        // get the packet content
        uint8_t* plaintext = nullptr;
        int plaintext_size = 0;
        generic_mi.decryptCiphertext(m_session_key, plaintext, plaintext_size);
        DownloadMi mi = DownloadMi::deserialize(plaintext, chunk_size);
        // mi.print(chunk_size);
        safeDelete(plaintext, DownloadMi::getSize(chunk_size));

        // check if the counter is correct
        if (mi.counter != m_counter)
            throw -2;

        incrementCounter();

        // copy chunk into the new local file
        requested_file.writeChunk(mi.chunk, chunk_size);
        
        received_bytes += chunk_size;
        LOG("(Download) Downloaded " << received_bytes << "bytes/" << requested_file.getFileSize() << "bytes");
        new_progress = ceil(((double)received_bytes / requested_file.getFileSize()) * 100);
        if (progress != new_progress) {
            cout << "Downloading..." << new_progress << "%" << endl;
        }
        progress = new_progress;
    }

    if (received_bytes != requested_file.getFileSize()) {
        return -8; 
    }

    return 0;
}

// ------------------------------------------------------------------------------

int Client::upload(string file_name) {

    // check if the file exists
    if (!FileManager::exists(file_name)) {
        cerr << "The requested file not exists in local filesystem" << endl;
        return -1; 
    }

    // open the file requested file
    FileManager file(file_name, READ);

    // check if the file size is zero
    if (file.getFileSize() == 0) {
        cerr << "An empty file can't be uploaded" << endl;
        return -2;
    }

    // check if the file size is over 4G
    size_t max_size = 4UL * 1024 * 1024 * 1024;
    if (file.getFileSize() > max_size) {
        cerr << "Is not possible to upload file larger than 4GB" << endl;
        return -3;
    }

    // create the M1 packet
    UploadM1 m1(m_counter, file_name, file.getFileSize());
    // m1.print();
    uint8_t* serialized_packet = m1.serialize();

    // create generic packet
    Generic generic_m1(m_session_key, m_hmac_key, serialized_packet, COMMAND_FIELD_PACKET_SIZE);
    safeDelete(serialized_packet, COMMAND_FIELD_PACKET_SIZE);
    // generic_m1.print();

    // 1.) send generic packet
    serialized_packet = generic_m1.serialize();
    int res = m_socket->send(serialized_packet, Generic::getSize(COMMAND_FIELD_PACKET_SIZE));
    delete[] serialized_packet;
    if (res < 0) {
        return -4;
    }

    incrementCounter();

    // 2.) receive the result packet
    serialized_packet = new uint8_t[Generic::getSize(Result::getSize())];
    res = m_socket->receive(serialized_packet, Generic::getSize(Result::getSize()));
    if (res < 0) {
        delete[] serialized_packet;
        return -5;
    }

    // deserialize the generic packet and verify the fingerprint
    Generic generic_m2 = Generic::deserialize(serialized_packet, Generic::getSize(Result::getSize()));
    delete[] serialized_packet;
    // generic_m2.print();
    bool verification_res = generic_m2.verifyHMAC(m_hmac_key);
    if (!verification_res) {
        LOG("(Upload) HMAC verification failed");
        return -6;
    }

    // get the M2 packet
    uint8_t* plaintext = nullptr;
    int plaintext_size = 0;
    generic_m2.decryptCiphertext(m_session_key, plaintext, plaintext_size);
    Result m2 = Result::deserialize(plaintext);
    // m2.print();
    safeDelete(plaintext, Result::getSize());

    // check if the counter is correct
    if (m2.counter != m_counter)
        throw -2;

    incrementCounter();

    // if the request failed stop
    if (m2.command_code == REQ_FAILED) {
        cerr << "The file already exists in the cloud" << endl;
        return -7;
    }

    size_t chunk_size = file.getChunkSize();
    size_t sent_size = 0;
    int progress = -1, new_progress;
    uint8_t* chunk_buffer = new uint8_t[chunk_size];

    // sent all file chunks
    for (size_t i = 0; i < file.getNumOfChunks(); ++i) {
        // get the chunk size
        if (i == file.getNumOfChunks() - 1)
            chunk_size = file.getLastChunkSize();

        // read the next chunk
        file.readChunk(chunk_buffer, chunk_size);

        // create the M3+i packet
        UploadMi mi(m_counter, chunk_buffer, chunk_size);
        // mi.print();
        serialized_packet = mi.serialize();

        // create generic packet
        Generic generic_mi(m_session_key, m_hmac_key, serialized_packet, UploadMi::getSize(chunk_size));
        safeDelete(serialized_packet, UploadMi::getSize(chunk_size));
        // generic_mi.print();

        // 3.) send generic packet
        serialized_packet = generic_mi.serialize();
        int res = m_socket->send(serialized_packet, Generic::getSize(UploadMi::getSize(chunk_size)));
        delete[] serialized_packet;
        if (res < 0) {
            return -8;
        }

        incrementCounter();

        // log upload status and progress percentage
        sent_size += chunk_size;
        LOG("(Upload) Uploaded " << sent_size << "bytes/" << file.getFileSize() << "bytes");
        new_progress = ceil(((double)sent_size / file.getFileSize()) * 100);
        if (progress != new_progress) {
            cout << "Uploading..." << new_progress << "%" << endl;
        }
        progress = new_progress;
    }

    // clean the buffer
    safeDelete(chunk_buffer, chunk_size);

    // 4.) receive the M4 packet
    serialized_packet = new uint8_t[Generic::getSize(Result::getSize())];
    res = m_socket->receive(serialized_packet, Generic::getSize(Result::getSize()));
    if (res < 0) {
        delete[] serialized_packet;
        return -9;
    }

    // deserialize the generic packet and verify the fingerprint
    Generic generic_mn = Generic::deserialize(serialized_packet, Generic::getSize(Result::getSize()));
    delete[] serialized_packet;
    // generic_mn.print();
    verification_res = generic_mn.verifyHMAC(m_hmac_key);
    if (!verification_res) {
        LOG("(Upload) HMAC verification failed");
        return -10;
    }

    // get the Mn packet
    plaintext = nullptr;
    plaintext_size = 0;
    generic_mn.decryptCiphertext(m_session_key, plaintext, plaintext_size);
    Result mn = Result::deserialize(plaintext);
    // mn.print();
    safeDelete(plaintext, Result::getSize());

    // check if the counter is correct
    if (mn.counter != m_counter)
        throw -2;

    incrementCounter();

    // return the status
    if (mn.command_code == REQ_FAILED) {
        LOG("(Upload) Failed with error code " << printErrorCodeDescription(mn.error_code));
        return -11;
    }

    return 0;
}

// ------------------------------------------------------------------------------

int Client::list() {

    // create the M1 packet
    ListM1 m1(m_counter);
    // m1.print();
    uint8_t* serialized_packet = m1.serialize();

    // create generic packet
    Generic generic_m1(m_session_key, m_hmac_key, serialized_packet, COMMAND_FIELD_PACKET_SIZE);
    safeDelete(serialized_packet, COMMAND_FIELD_PACKET_SIZE);
    // generic_m1.print();

    // 1.) send generic packet
    serialized_packet = generic_m1.serialize();
    int res = m_socket->send(serialized_packet, Generic::getSize(COMMAND_FIELD_PACKET_SIZE));
    delete[] serialized_packet;
    if (res < 0) {
        return -1;
    }

    LOG("(List) Sent M1 packet");

    incrementCounter();

    // 2.) receive the generic packet
    serialized_packet = new uint8_t[Generic::getSize(ListM2::getSize())];
    res = m_socket->receive(serialized_packet, Generic::getSize(ListM2::getSize()));
    if (res < 0) {
        delete[] serialized_packet;
        return -2;
    }

    // deserialize the generic packet and verify the fingerprint
    Generic generic_m2 = Generic::deserialize(serialized_packet, Generic::getSize(ListM2::getSize()));
    delete[] serialized_packet;
    // generic_m2.print();
    bool verification_res = generic_m2.verifyHMAC(m_hmac_key);
    if (!verification_res) {
        LOG("(List) HMAC verification failed");
        return -3;
    }

    LOG("(List) Received M2 valid packet");

    // get the m2 packet
    uint8_t* plaintext = nullptr;
    int plaintext_size = 0;
    generic_m2.decryptCiphertext(m_session_key, plaintext, plaintext_size);
    ListM2 m2 = ListM2::deserialize(plaintext);
    // m2.print();
    safeDelete(plaintext, ListM2::getSize());

    // check if the counter is correct
    if (m2.counter != m_counter)
        throw -2;

    incrementCounter();

    // 3.) receive the generic packet
    serialized_packet = new uint8_t[Generic::getSize(ListM3::getSize(m2.file_list_size))];
    res = m_socket->receive(serialized_packet, Generic::getSize(ListM3::getSize(m2.file_list_size)));
    if (res < 0) {
        delete[] serialized_packet;
        return -4;
    }

    // deserialize the generic packet and verify the fingerprint
    Generic generic_m3 = Generic::deserialize(serialized_packet, Generic::getSize(ListM3::getSize(m2.file_list_size)));
    delete[] serialized_packet;
    // generic_m3.print();
    verification_res = generic_m3.verifyHMAC(m_hmac_key);
    if (!verification_res) {
        LOG("(List) HMAC verification failed");
        return -5;
    }

    LOG("(List) Received M3 valid packet");

    // get the m3 packet
    plaintext = nullptr;
    plaintext_size = 0;
    generic_m3.decryptCiphertext(m_session_key, plaintext, plaintext_size);
    ListM3 m3 = ListM3::deserialize(plaintext, plaintext_size);
    // m3.print();
    safeDelete(plaintext, ListM3::getSize(m2.file_list_size));

    // check if the counter is correct
    if (m3.counter != m_counter) 
        throw -2;

    incrementCounter();

    //print file list
    cout << "----------- LIST -------------" << endl;
    string file_name = "";
    for(int i = 0; i < (int)m2.file_list_size; i++){
        if ((char)m3.available_files[i] == '|' || i == (int)m2.file_list_size - 1){
            cout << file_name << endl;
            file_name = "";
        }
        else
            file_name = file_name + (char)m3.available_files[i];
    }
    cout << "------------------------------" << endl;

    return 0;
}

// ------------------------------------------------------------------------------

int Client::rename(string file_name, string new_file_name) {

    // create the M1 packet
    RenameM1 m1(m_counter, file_name, new_file_name);
    // m1.print();
    uint8_t* serialized_packet = m1.serialize();

    // create generic packet
    Generic generic_m1(m_session_key, m_hmac_key, serialized_packet, COMMAND_FIELD_PACKET_SIZE);
    safeDelete(serialized_packet, COMMAND_FIELD_PACKET_SIZE);
    // generic_m1.print();

    // 1.) send generic packet
    serialized_packet = generic_m1.serialize();
    int res = m_socket->send(serialized_packet, Generic::getSize(COMMAND_FIELD_PACKET_SIZE));
    delete[] serialized_packet;
    if (res < 0) {
        return -1;
    }

    incrementCounter();

    LOG("(Rename) Sent M1 packet");

    // 2.) receive the generic packet
    serialized_packet = new uint8_t[Generic::getSize(Result::getSize())];
    res = m_socket->receive(serialized_packet, Generic::getSize(Result::getSize()));
    if (res < 0) {
        delete[] serialized_packet;
        return -2;
    }

    // deserialize the generic packet and verify the fingerprint
    Generic generic_m2 = Generic::deserialize(serialized_packet, Generic::getSize(Result::getSize()));
    delete[] serialized_packet;
    // generic_m2.print();
    bool verification_res = generic_m2.verifyHMAC(m_hmac_key);
    if (!verification_res) {
        LOG("(Rename) HMAC verification failed");
        return -3;
    }

    LOG("(Rename) Received valid M2 packet");

    // get the m2 packet
    uint8_t* plaintext = nullptr;
    int plaintext_size = 0;
    generic_m2.decryptCiphertext(m_session_key, plaintext, plaintext_size);
    Result m2 = Result::deserialize(plaintext);
    // m2.print();
    safeDelete(plaintext, Result::getSize());

    // check if the counter is correct
    if (m2.counter != m_counter) 
        throw -2;

    incrementCounter();

    // check if operation failed
    if (m2.command_code == REQ_SUCCESS)
        return 0;
    else if (m2.command_code == REQ_FAILED){
        switch(m2.error_code){
            case FILE_NOT_FOUND_ERROR:
                cerr << "File not found" << endl;
                break;
            case FILE_ALREADY_EXISTS_ERROR:
                cerr << "File with the new file name already exists" << endl;
                break;
            case RENAME_FAILED_ERROR:
                cerr << "Rename operation failed" << endl;
                break;
        }
        return -4;
    }

    return -5;
}

// ------------------------------------------------------------------------------

int Client::remove(string file_name) {

    // create the M1 packet
    RemoveM1 m1(m_counter, file_name);
    // m1.print();
    uint8_t* serialized_packet = m1.serialize();

    // create generic packet
    Generic generic_m1(m_session_key, m_hmac_key, serialized_packet, COMMAND_FIELD_PACKET_SIZE);
    safeDelete(serialized_packet, COMMAND_FIELD_PACKET_SIZE);
    // generic_m1.print();

    // 1.) send generic packet
    serialized_packet = generic_m1.serialize();
    int res = m_socket->send(serialized_packet, Generic::getSize(COMMAND_FIELD_PACKET_SIZE));
    delete[] serialized_packet;
    if (res < 0) {
        return -1;
    }

    incrementCounter();

    LOG("(Remove) Sent M1 packet");

    // 2.) receive the generic packet
    serialized_packet = new uint8_t[Generic::getSize(Result::getSize())];
    res = m_socket->receive(serialized_packet, Generic::getSize(Result::getSize()));
    if (res < 0) {
        delete[] serialized_packet;
        return -2;
    }

    // deserialize the generic packet and verify the fingerprint
    Generic generic_m2 = Generic::deserialize(serialized_packet, Generic::getSize(Result::getSize()));
    delete[] serialized_packet;
    // generic_m2.print();
    bool verification_res = generic_m2.verifyHMAC(m_hmac_key);
    if (!verification_res) {
        LOG("(Remove) HMAC verification failed");
        return -3;
    }

    LOG("(Remove) Received valid M2 packet");

    // get the m2 packet
    uint8_t* plaintext = nullptr;
    int plaintext_size = 0;
    generic_m2.decryptCiphertext(m_session_key, plaintext, plaintext_size);
    Result m2 = Result::deserialize(plaintext);
    // m2.print();
    safeDelete(plaintext, Result::getSize());

    // check if the counter is correct
    if (m2.counter != m_counter) 
        throw -2;

    incrementCounter();

    // check if operation failed
    if (m2.command_code == REQ_SUCCESS)
        return 0;
    else if (m2.command_code == REQ_FAILED){
        switch(m2.error_code){
            case FILE_NOT_FOUND_ERROR:
                cerr << "File not found" << endl;
                break;
            case DELETE_FAILED_ERROR:
                cerr << "Delete operation failed" << endl;
                break;
        }
        return -4;
    }

    return -5;
}

// ------------------------------------------------------------------------------

void Client::incrementCounter() {

    // check if renegotiation is needed
    if (m_counter == MAX_COUNTER_VALUE) {
        int res = login();
        if (res != 0)
            throw -1;
    } else {
        m_counter++;
    }
}

int Client::run() {

    // --------------- INITIALIZATION ---------------

    string password;
    cout << "Insert username: ";
    cin >> m_username;
    cout << "Insert password: ";
    cin >> password;
    
    if (m_username.length() == 0 || password.length() == 0)
        return 1;

    // sanitize username and password
    static char ok_chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-.@?!#*";
    if (strspn(m_username.c_str(), ok_chars) < strlen(m_username.c_str())) { 
        cerr << "Invalid username" << endl;
        return -1;
    }
    if (strspn(password.c_str(), ok_chars) < strlen(password.c_str())) { 
        cerr << "Invalid password" << endl;
        return -2;
    }
    if (m_username.length() >= USERNAME_SIZE) {
        cerr << "Username too long" << endl;
        return -3;
    } 

    // open the private key PEM file
    string private_key_file = "resources/encrypted_keys/" + m_username + "_key.pem";
    BIO *bio = BIO_new_file(private_key_file.c_str(), "r");
    if (!bio) {
        cerr << "No long term key associated to the username" << endl;
        return -4;
    }
    
    // encrypt and save the long term private key
    m_long_term_key = PEM_read_bio_PrivateKey(bio, 0, 0, (void *)password.c_str());
    BIO_free(bio);

    // check if the password is correct
    if (!m_long_term_key) {
        cerr << "Wrong password" << endl;
        return -5;
    }

    // connect to the server
    try {
        m_socket = new CommunicationSocket(SERVER_IP, SERVER_PORT);
    } catch (const exception& e) {
        LOG("(Run) Exception: " << e.what());
        cerr << "Connection to the server failed" << endl;
        return -6;
    }

    // ----------------------------------------------

    int res = login();
    if (res != 0) {
        LOG("(Run) Login failed with error code " << res);
        cerr << "Something went wrong" << endl;
        return -7;
    }
    cout << "Login completed" << endl;

    try {
        while (1) {
            
            string command;
            cout << "Insert next command: ";
            cin >> command;

            // needed in case of SIGINT
            if (command.length() == 0) {
                logout();
                return 1;
            }

            if (command == "list") {
                res = list();
                if (res < 0) {
                    LOG("(Run) List failed with error code " << res);
                    cerr << "Something went wrong" << endl;
                }
            }

            else if (command == "download") {

                string file_name;
                cout << "File to download: ";
                cin >> file_name;

                // sanitize filename
                res = FileManager::sanitizeFileName(file_name);
                if (res == -1) {
                    cerr << "Invalid file name" << endl;
                    continue;
                } else if (res == -2) {
                    cerr << "The file name can't be '.'" << endl;
                    continue;
                } else if (res == -3) {
                    cerr << "The file name can't be '..'" << endl;
                    continue;
                } else if (res == -4) {
                    cerr << "The file name can't be longer than " << FILE_NAME_SIZE << " characters" << endl;
                    continue;
                }

                res = download(file_name);
                if (res < 0) {
                    LOG("(Run) Download failed with error code " << res);
                    if (res < -1 && res != -5)
                        cerr << "Something went wrong" << endl;
                } else {
                    cout << "Download completed" << endl;
                }
            }

            else if (command == "upload") {
                
                string file_name;
                cout << "Insert the name of the file: ";
                cin >> file_name;

                // sanitize filename
                res = FileManager::sanitizeFileName(file_name);
                if (res == -1) {
                    cerr << "Invalid file name" << endl;
                    continue;
                } else if (res == -2) {
                    cerr << "The file name can't be '.'" << endl;
                    continue;
                } else if (res == -3) {
                    cerr << "The file name can't be '..'" << endl;
                    continue;
                } else if (res == -4) {
                    cerr << "The file name can't be longer than " << FILE_NAME_SIZE << " characters" << endl;
                    continue;
                }

                // check if the path isn't a regular file (folder, symlink, ecc...)
                if (!filesystem::is_regular_file(filesystem::path(file_name))) {
                    cerr << "The file name doesn't correspond to a regular file" << endl;
                    continue;
                }

                res = upload(file_name);
                if (res < 0) {
                    LOG("(Run) Upload failed with error code " << res);
                    if (res < -3 && res != -7)
                        cerr << "Something went wrong" << endl;
                } else {
                    cout << "Upload completed" << endl;
                }
            }

            else if (command == "rename") {
                // get input from user
                string file_name, new_file_name;
                cout << "Insert file name: ";
                cin >> file_name;
                cout << "Insert new file name: ";
                cin >> new_file_name;
                
                // sanitize file_name
                res = FileManager::sanitizeFileName(file_name);
                if (res == -1) {
                    cerr << "Invalid file name" << endl;
                    continue;
                } else if (res == -2) {
                    cerr << "The file name can't be '.'" << endl;
                    continue;
                } else if (res == -3) {
                    cerr << "The file name can't be '..'" << endl;
                    continue;
                } else if (res == -4) {
                    cerr << "The file name can't be longer than " << FILE_NAME_SIZE << " characters" << endl;
                    continue;
                }
                
                // sanitize new_file_name
                res = FileManager::sanitizeFileName(new_file_name);
                if (res == -1) {
                    cerr << "Invalid new file name" << endl;
                    continue;
                } else if (res == -2) {
                    cerr << "The new file name can't be '.'" << endl;
                    continue;
                } else if (res == -3) {
                    cerr << "The new file name can't be '..'" << endl;
                    continue;
                } else if (res == -4) {
                    cerr << "The new file name can't be longer than " << FILE_NAME_SIZE << " characters" << endl;
                    continue;
                }
                
                if(file_name == new_file_name) {
                    cerr << "File name and new file name can't be equal" << endl;
                    continue;
                }

                res = rename(file_name, new_file_name);
                if (res < 0) {
                    LOG("(Run) Rename failed with error code " << res);
                    if (res != -4)
                        cerr << "Something went wrong" << endl;
                } else {
                    cout << "Rename completed" << endl;
                }
            }

            else if (command == "delete") {
                // get input from user
                string file_name;
                cout << "Insert file name: ";
                cin >> file_name;
                
                // sanitize file_name
                res = FileManager::sanitizeFileName(file_name);
                if (res == -1) {
                    cerr << "Invalid file name" << endl;
                    continue;
                } else if (res == -2) {
                    cerr << "The file name can't be '.'" << endl;
                    continue;
                } else if (res == -3) {
                    cerr << "The file name can't be '..'" << endl;
                    continue;
                } else if (res == -4) {
                    cerr << "The file name can't be longer than " << FILE_NAME_SIZE << " characters" << endl;
                    continue;
                }
    
                res = remove(file_name);
                if (res < 0) {
                    LOG("(Run) Delete failed with error code " << res);
                    if (res != -4)
                        cerr << "Something went wrong" << endl;
                } else {
                    cout << "Delete completed" << endl;
                }
            }

            else if (command == "logout" || command == "exit") {
                res = logout();
                if (res < 0) {
                    LOG("(Run) Logout failed with error code " << res);
                    cerr << "Something went wrong" << endl;
                    continue;
                } 

                cout << "Logout completed" << endl;

                if (command == "exit") 
                    return 1;
                return 0;
            }
            
            else if (command == "help") {
                cout << "----------- COMMANDS -----------" << endl;
                cout << "list" << endl;
                cout << "download" << endl;
                cout << "upload" << endl;
                cout << "rename" << endl;
                cout << "delete" << endl;
                cout << "logout" << endl;
                cout << "exit" << endl;
                cout << "--------------------------------" << endl;
            } 
            
            else {
                cerr << "Invalid command" << endl;
            } 
        }
    } catch (int e) {

        if (e == -1) {
            LOG("(Run) Renegotiation failed");
        } else if (e == -2) {
            LOG("(Run) Replay attack detected");
        } else if (e == -3) {
            logout();
            LOG("(Run) Client close");
            return 1;
        } else if (e == -4) {
            LOG("(Run) Socket closed unexpectedly");
        }

        cerr << "Something went wrong" << endl;
        return -9;
    }

    return 0;
}