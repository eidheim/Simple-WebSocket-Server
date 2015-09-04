Simple-WebSocket-Server
=================

A very simple, fast, multithreaded, platform independent WebSocket (WS) and WebSocket Secure (WSS) server and client library implemented using C++11, Boost.Asio and OpenSSL. Created to be an easy way to make WebSocket endpoints in C++.

See also https://github.com/eidheim/Simple-Web-Server for an easy way to make REST resources available from C++ applications. 

### Backward compatibility note
**Current master branch is not backward compatible with prior versions. Prior versions had problems with moving buffer pointers when sending large and complex streams.**

### Features

* RFC 6455 mostly supported: text/binary frames, ping-pong, connection close with status and reason.
* Thread pool
* Platform independent
* WebSocket Secure support
* Timeouts, if any of SocketServer::timeout_request and SocketServer::timeout_idle are >0 (default: SocketServer::timeout_request=5 seconds, and SocketServer::timeout_idle=0 seconds; no timeout on idle connections)
* Simple way to add WebSocket endpoints using regex for path, and anonymous functions
* An easy to use WebSocket and WebSocket Secure client library
* C++ bindings to the following OpenSSL methods: Base64, MD5, SHA1, SHA256 and SHA512 (found in crypto.hpp)

### TODO
* Data from client is currently moved to a separate stream while doing masking. This should happen in the stream instead using a custom stream buffer.

###Usage

See ws_examples.cpp or wss_examples.cpp for example usage. 

### Dependencies

Boost C++ libraries must be installed, go to http://www.boost.org for download and instructions. 

OpenSSL libraries from https://www.openssl.org are required. 

### Compile and run

ws_examples.cpp and wss_examples.cpp use C++14 features.

Compile with a C++14 compiler supporting regex (for instance g++ 4.9):

On Linux using g++: add `-pthread`

You can now also compile using CMake and make:

```
cmake .
make
```

#### WS

`g++ -O3 -std=c++1y ws_examples.cpp -lboost_system -lcrypto -o ws_examples`

Then to run the server and client examples: `./ws_examples`

#### WSS

`g++ -O3 -std=c++1y wss_examples.cpp -lboost_system -lssl -lcrypto -o wss_examples`

Before running, an RSA private key (server.key) and an SSL certificate (server.crt) must be created. Follow, for instance, the instructions given here (for a self-signed certificate): http://www.akadia.com/services/ssh_test_certificate.html

Then to run the server and client examples: `./wss_examples`
