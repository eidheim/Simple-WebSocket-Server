#include "server_ws.hpp"

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
    echo.onmessage=[&server](auto connection) {
        //To receive message from client as string (message_stream.str())
        stringstream message_stream;
        *connection->message >> message_stream.rdbuf();
        
        string response=message_stream.str()+" from socket "+to_string((size_t)&connection->socket);
        
        stringstream response_stream;
        response_stream << response;
        
        //server.send is an asynchronous function
        server.send(connection, response_stream, [](const boost::system::error_code& ec){
            if(!ec)
                cout << "Message sent successfully" << endl;
            else {
                cout << "Error sending message. ";
                //See http://www.boost.org/doc/libs/1_55_0/doc/html/boost_asio/reference.html, Error Codes for error code meanings
                cout << "Error: " << ec << ", error message: " << ec.message() << endl;
           }
        });
    };
    
    echo.onopen=[&server](auto connection) {
        cout << "Opened connection to socket " << (size_t)&connection->socket << endl;
    };
    
    //See RFC 6455 7.4.1. for status codes
    echo.onclose=[](auto connection, int status) {
        cout << "Closed connection to socket " << (size_t)&connection->socket << " with status code " << status << endl;
    };
    
    //See http://www.boost.org/doc/libs/1_55_0/doc/html/boost_asio/reference.html, Error Codes for error code meanings
    echo.onerror=[](auto connection, const boost::system::error_code& ec) {
        cout << "Error in connection to socket " << (size_t)&connection->socket << ". ";
        cout << "Error: " << ec << ", error message: " << ec.message() << endl;
    };
    

    //Example 2: Echo to all WebSocket endpoints
    //  Sending received messages to all connected clients
    //  Test with the following JavaScript on more than one browser windows:
    //    var ws=new WebSocket("ws://localhost:8080/echo_all");
    //    ws.onmessage=function(evt){console.log(evt.data);};
    //    ws.send("test");
    auto& echo_all=server.endpoint["^/echo_all/?$"];
    echo_all.onmessage=[&server](auto connection) {
        //To receive message from client as string (message_stream.str())
        stringstream message_stream;
        *connection->message >> message_stream.rdbuf();
        
        string response=message_stream.str()+" from socket "+to_string((size_t)&connection->socket);
        
        for(auto connection: server.get_connections()) {
            stringstream response_stream;
            response_stream << response;
            
            //server.send is an asynchronous function
            server.send(connection, response_stream);
        }
    };
    
    //Start WS-server
    server.start();
    
    return 0;
}