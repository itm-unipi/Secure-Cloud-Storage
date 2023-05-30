<p align="center">
  <img src="https://cdn-icons-png.flaticon.com/512/3812/3812209.png" alt="SCS-Logo" height="64px"/>
</p>

# Secure Cloud Storage

University Project for "Foundations of Cybersecurity" course (MSc Computer Engineering @ University of Pisa). Implementation of a Secure Cloud Storage using `C++ 17` and `OpenSSL 1.1.1` library.

## Overview

The project consists of a **secure cloud storage**. Each **client** connects to a centralized **server** that allows to perform operations on its **private** dedicated storage. In order to access to his storage, a user must **login**, after that he can execute the following operations:

* **List**: shows all files currently on the storage
* **Download**: retrieves a file from the storage to the local file system
* **Upload**: loads a file from the local file system to the storage
* **Rename**: changes the name of a file on the storage
* **Delete**: removes a file from the storage
* **Logout**: closes the connection to the server

The login operation creates a **secure connection** between the server and a client through the negotiation of a set of **session keys**.

The cloud storage application has to guarantee the following requirements:

* The key negotiation has to provide the *Perfect Forward Secrecy*
* The client and server communication has to be **encrypted** and **authenticated**
* The client and server communication has to be protected against **reply attacks**

Client and server authenticate each other using their own **public keys**. The server already knows all the registered users’ keys and the client retrieves the server’s key through the **certificate** released by a **Certification Authority**.

## Getting Started

In order to compile the project, `openssl-1.1.1` is needed with the development library:

```bash
sudo apt install libssl-dev 
```

To **compile** the project:

```bash
mkdir bin
make
```

To **run** the project:

```bash
bin/server
bin/client
```

## Project Architecture

```
Secure-Cloud-Storage
├── data
│   ├── biagio
│   ├── gianluca
│   └── matteo
├── docs
├── resources
│   ├── certificates
│   ├── Config.h
│   ├── encrypted_keys
│   ├── private_keys
│   └── public_keys
├── script
└── src
    ├── client
    ├── packet
    ├── security
    ├── server
    └── utility
```

## Authors

* Biagio Cornacchia, b.cornacchia@studenti.unipi.it
* Gianluca Gemini, g.gemini@studenti.unipi.it
* Matteo Abaterusso, m.abaterusso@studenti.unipi.it
