Simple-WebSocket-Sample
=======================

This sample project contains two executables which allow the user to control the connections and message flow for Simple-WebSocket-Server.  It might be useful for testing interoperability with other websockets implementations.

The following actions are supported.

### sample_server

 s :  Start server
 t :  sTop server
 m :  send Message to all clients
 q :  Quit

### sample_client

 s :  Set up connection
 l :  cLose connection
 c :  stop Client
 m :  send Message
 q :  Quit

## Usage

Run one server and as many clients as you like.  Type the letter for the desired action and hit enter.

## Building

The sample uses [Simple-WebSocket-Server](../README.md) (duh).  You'll need its dependencies installed.


#### Windows

Populate the following environmentla variables

| variable | value |
|:--|:--|
| BoostRoot | C:\path\to\Boost |
| BoostVer | 1_62 |
| OpenSSLRoot | C:\path\to\OpenSSL |

Specify the correct generator in your call to cmake

    mkdir build
    cd build
    cmake .. -G "Visual Studio 15 2017 Win64"

Open `build/Simple_WebSocket_Sample.sln` and build it

#### Linux

    mkdir build
    cd build 
    cmake ..
