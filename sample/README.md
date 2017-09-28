Simple-WebSocket-Sample
=======================

This project contains two executables which allow the user to control the connections and message flow for Simple-WebSocket-Server.  It might be useful for testing interoperability with other websockets implementations.

### sample_server controls

    s :  Start server
    t :  sTop server
    m :  send Message to all clients
    q :  Quit

### sample_client controls

    s :  Set up connection
    l :  cLose connection
    c :  stop Client
    m :  send Message
    q :  Quit

## Usage

Run one server and as many clients as you like.  Type the letter for the desired action and hit enter. A typical session might look like this:

| sample_client | sample_server | Effect |
| :-----------: | :------------:|:-------|
|               | **S**tart     | The server starts listening for connections |
| **S**tart     |               | The client connects to the server |
| **M**essage   |               | The client sends a message to the server (the server will respond with an echo) |
|               | **M**essage   | The server sends a message to all connected clients (they will not respond) |
| c**L**ose     |               | The client disconnects with a message |
|               | s**T**op      | The server stops listening |
| s**T**op      |               | The client cleans itself up |
| **Q**uit      |               | The client quits |
|               | **Q**uit      | The server quits |
## Building

The sample uses [Simple-WebSocket-Server](../README.md) (duh).  You'll need its dependencies installed.


#### Windows

Populate the following environmentla variables:

| variable | value |
|:--|:--|
| BoostRoot | C:\path\to\Boost |
| BoostVer | 1_62 |
| OpenSSLRoot | C:\path\to\OpenSSL |

Specify the correct generator in your call to cmake, this example uses 2017 with a 64 bit build:

    mkdir build
    cd build
    cmake .. -G "Visual Studio 15 2017 Win64"

Open in your IDE of choice `build/Simple_WebSocket_Sample.sln` and build it.

#### Linux

    mkdir build
    cd build 
    cmake ..
