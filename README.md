Simple-WebSocket-Server
=================

A very simple, fast, multithreaded, platform independent WebSocket (WS) and WebSocket Secure (WSS) server implemented using C++11, Boost.Asio and OpenSSL. Created to be an easy way to make WebSocket endpoints in C++.

See also https://github.com/eidheim/Simple-Web-Server for an easy way to make REST resources available from C++ applications. 

### Features

* Thread pool
* Platform independent
* WebSocket Secure support
* Simple way to add WebSocket endpoints using regex for path, and anonymous functions
* C++ bindings to the following OpenSSL methods: Base64, MD5, SHA1, SHA256 and SHA512 (found in crypt.hpp)

###Usage

See main_ws.cpp or main_wss.cpp for example usage. 

### Dependencies

Boost C++ libraries must be installed, go to http://www.boost.org for download and instructions. 

OpenSSL libraries from https://www.openssl.org are required. 

Will update to use C++17 networking instead in the future when it is supported by g++. 

### Compile and run

Compile with a C++11 compiler supporting regex (for instance g++ 4.9):

#### WS

g++ -O3 -std=c++11 -lboost_system -lcrypto main_ws.cpp -o ws_server

Then to run the server: ./ws_server

#### WSS

g++ -O3 -std=c++11 -lboost_system -lssl -lcrypto main_wss.cpp -o wss_server

Before running the server, an RSA private key (server.key) and an SSL certificate (server.crt) must be created. Follow, for instance, the instructions given here (for a self-signed certificate): http://www.akadia.com/services/ssh_test_certificate.html

Then to run the server: ./wss_server
