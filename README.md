Simple-WebSocket-Server
=================

A very simple, fast, multithreaded, platform independent WebSocket (WS) and WebSocket Secure (WSS) server and client library implemented using C++11, Boost.Asio and OpenSSL. Created to be an easy way to make WebSocket endpoints in C++.

See https://github.com/eidheim/Simple-Web-Server for an easy way to make REST resources available from C++ applications. Also, feel free to check out the new C++ IDE supporting C++11/14/17: https://github.com/cppit/jucipp. 

### Features

* RFC 6455 mostly supported: text/binary frames, ping-pong, connection close with status and reason.
* Thread pool
* Platform independent
* WebSocket Secure support
* Timeouts, if any of SocketServer::timeout_request and SocketServer::timeout_idle are >0 (default: SocketServer::timeout_request=5 seconds, and SocketServer::timeout_idle=0 seconds; no timeout on idle connections)
* Simple way to add WebSocket endpoints using regex for path, and anonymous functions
* An easy to use WebSocket and WebSocket Secure client library
* C++ bindings to the following OpenSSL methods: Base64, MD5, SHA1, SHA256 and SHA512 (found in crypto.hpp)

###Usage

See ws_examples.cpp or wss_examples.cpp for example usage. 

### Dependencies

* Boost C++ libraries 
* OpenSSL libraries

### Compile

Compile with a C++11 supported compiler:

```sh
cmake .
make
```

#### Run server and client examples

### WS

```sh
./ws_examples
```

### WSS

Before running the WSS-examples, an RSA private key (server.key) and an SSL certificate (server.crt) must be created. Follow, for instance, the instructions given here (for a self-signed certificate): http://www.akadia.com/services/ssh_test_certificate.html

Then:
```
./wss_examples
```
