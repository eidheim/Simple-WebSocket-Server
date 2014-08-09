/*#include "server_ws.hpp"
#include "client_ws.hpp"

using namespace std;
using namespace SimpleWeb;

int main() {
    //WebSocket (WS)-server at port 8080 using 4 threads
    Server<WS> server(8080, 4);
    
    //Example 1: echo WebSocket endpoint
    //  Added debug messages for example use of the callbacks
    //  Test with the following JavaScript:
    //    var ws=new WebSocket("ws://localhost:8080/echo");
    //    ws.onmessage=function(evt){console.log(evt.data);};
    //    ws.send("test");
    auto& echo=server.endpoint["^/echo/?$"];
    
    //C++14, lambda parameters declared with auto
    //For C++11 use: (shared_ptr<Server<WS>::Connection> connection, std::shared_ptr<std::istream> message, size_t message_length)
    echo.onmessage=[&server](auto connection, auto message, size_t message_length) {
        //To receive message from client as string (message_stream.str())
        stringstream message_stream;
        *message >> message_stream.rdbuf();
        
        cout << "Server: Message received: \"" << message_stream.str() << "\"" << endl;;
                
        cout << "Server: Sending message \"" << message_stream.str() <<  "\" to " << (size_t)connection.get() << endl;
        
        //server.send is an asynchronous function
        server.send(connection, message_stream, [](const boost::system::error_code& ec){
            if(ec) {
                cout << "Server: Error sending message. " <<
                //See http://www.boost.org/doc/libs/1_55_0/doc/html/boost_asio/reference.html, Error Codes for error code meanings
                        "Error: " << ec << ", error message: " << ec.message() << endl;
           }
        });
    };
    
    echo.onopen=[](auto connection) {
        cout << "Server: Opened connection " << (size_t)connection.get() << endl;
    };
    
    //See RFC 6455 7.4.1. for status codes
    echo.onclose=[](auto connection, int status) {
        cout << "Server: Closed connection " << (size_t)connection.get() << " with status code " << status << endl;
    };
    
    //See http://www.boost.org/doc/libs/1_55_0/doc/html/boost_asio/reference.html, Error Codes for error code meanings
    echo.onerror=[](auto connection, const boost::system::error_code& ec) {
        cout << "Server: Error in connection " << (size_t)connection.get() << ". " << 
                "Error: " << ec << ", error message: " << ec.message() << endl;
    };
    

    //Example 2: Echo to all WebSocket endpoints
    //  Sending received messages to all connected clients
    //  Test with the following JavaScript on more than one browser windows:
    //    var ws=new WebSocket("ws://localhost:8080/echo_all");
    //    ws.onmessage=function(evt){console.log(evt.data);};
    //    ws.send("test");
    auto& echo_all=server.endpoint["^/echo_all/?$"];
    echo_all.onmessage=[&server](auto connection, auto message, size_t message_length) {
        //To receive message from client as string (message_stream.str())
        stringstream message_stream;
        *message >> message_stream.rdbuf();
        
        for(auto a_connection: server.get_connections()) {
            stringstream response_stream;
            response_stream << message_stream.str();
            
            //server.send is an asynchronous function
            server.send(a_connection, response_stream);
        }
    };
    
    thread server_thread([&server](){
        //Start WS-server
        server.start();
    });
    
    //Wait for server to start so that the client can connect
    this_thread::sleep_for(chrono::seconds(1));
    
    //Example 3: Client communication with server
    //Possible output:
    //Server: Opened connection 140243756912112
    //Client: Opened connection
    //Client: Sending message: "Hello"
    //Server: Message received: "Hello"
    //Server: Sending message "Hello" to 140243756912112
    //Client: Message received: "Hello"
    //Client: Sending close connection
    //Server: Closed connection 140243756912112 with status code 1000
    //Client: Closed connection with status code 1000
    Client<WS> client("localhost:8080/echo");
    client.onmessage=[&client](auto message, size_t message_length) {
        cout << "Client: Message received: \"" << message->rdbuf() << "\"" << endl;
        
        cout << "Client: Sending close connection" << endl;
        client.send_close(1000);
    };
    
    client.onopen=[&client]() {
        cout << "Client: Opened connection" << endl;
        
        stringstream ss;
        ss << "Hello";
        cout << "Client: Sending message: \"" << ss.str() << "\"" << endl;
        client.send(ss);
    };
    
    client.onclose=[](int status) {
        cout << "Client: Closed connection with status code " << status << endl;
    };
    
    //See http://www.boost.org/doc/libs/1_55_0/doc/html/boost_asio/reference.html, Error Codes for error code meanings
    client.onerror=[](const boost::system::error_code& ec) {
        cout << "Client: Error: " << ec << ", error message: " << ec.message() << endl;
    };
    
    client.start();
    
    server_thread.join();
    
    return 0;
}*/