Simple-WebSocket-Server
=================

A very simple, fast, multithreaded, platform independent WebSocket (WS) and WebSocket Secure (WSS) server and client library implemented using C++11, Boost.Asio and OpenSSL. Created to be an easy way to make WebSocket endpoints in C++.

See also https://github.com/eidheim/Simple-Web-Server for an easy way to make REST resources available from C++ applications. 

### Features

* Most common parts of RFC 6455 are supported: single fragment text/binary messages.
* Thread pool
* Platform independent
* WebSocket Secure support
* Timeouts, if any of Server::timeout_request and Server::timeout_idle are >0 (default: Server::timeout_request=5 seconds, and Server::timeout_idle=0 seconds; no timeout on idle connections)
* Simple way to add WebSocket endpoints using regex for path, and anonymous functions
* An easy to use WebSocket and WebSocket Secure client library
* C++ bindings to the following OpenSSL methods: Base64, MD5, SHA1, SHA256 and SHA512 (found in crypto.hpp)

###Usage

See main_ws.cpp or main_wss.cpp for example usage. 

### Dependencies

Boost C++ libraries must be installed, go to http://www.boost.org for download and instructions. 

OpenSSL libraries from https://www.openssl.org are required. 

### Compile and run

main_ws.cpp and main_wss.cpp use C++14 features.

Compile with a C++14 compiler supporting regex (for instance g++ 4.9):

#### WS

g++ -O3 -std=c++1y -lboost_system -lcrypto main_ws.cpp -o ws

Then to run the server: ./ws

#### WSS

g++ -O3 -std=c++1y -lboost_system -lssl -lcrypto main_wss.cpp -o wss

Before running the test, an RSA private key (server.key) and an SSL certificate (server.crt) must be created. Follow, for instance, the instructions given here (for a self-signed certificate): http://www.akadia.com/services/ssh_test_certificate.html

Then to run the server: ./wss
