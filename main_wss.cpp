#include "server_wss.hpp"

using namespace std;
using namespace SimpleWeb;

int main() {
    //WebSocket Secure (WSS)-server at port 8080 using 4 threads
    Server<WSS> server(8080, 4, "server.crt", "server.key");
    
    //Example 1: echo WebSocket Secure endpoint
    //  Added debug messages for example use of the callbacks
    //  Test with the following JavaScript:
    //    var wss=new WebSocket("wss://localhost:8080/echo");
    //    wss.onmessage=function(evt){console.log(evt.data);};
    //    wss.send("test");
    auto& callbacks_echo=server.endpoint["^/echo/?$"];
    
    callbacks_echo.onmessage=[&server](Connection& connection) {
        //To receive message from client as string (message_stream.str())
        stringstream message_stream;
        *connection.message >> message_stream.rdbuf();
        
        string response=message_stream.str()+" from "+to_string((size_t)connection.id);
        
        stringstream response_stream;
        response_stream << response;
        
        //server.send is an asynchronous function
        server.send(connection.id, response_stream, [](const boost::system::error_code& ec){
            if(!ec)
                cout << "Message sent successfully" << endl;
            else {
                cout << "Error sending message. ";
                //See http://www.boost.org/doc/libs/1_55_0/doc/html/boost_asio/reference.html, Error Codes for error code meanings
                cout << "Error: " << ec << ", error message: " << ec.message() << endl;
           }
        });
    };
    
    callbacks_echo.onopen=[&server](Connection& connection) {
        cout << "Opened connection to " << (size_t)connection.id << endl;
    };
    
    //See RFC 6455 7.4.1. for status codes
    callbacks_echo.onclose=[](Connection& connection, int status) {
        cout << "Closed connection to " << (size_t)connection.id << " with status code " << status << endl;
    };
    
    //See http://www.boost.org/doc/libs/1_55_0/doc/html/boost_asio/reference.html, Error Codes for error code meanings
    callbacks_echo.onerror=[](Connection& connection, const boost::system::error_code& ec) {
        cout << "Error in connection " << (size_t)connection.id << ". ";
        cout << "Error: " << ec << ", error message: " << ec.message() << endl;
    };
    

    //Example 2: Echo to all WebSocket Secure endpoints
    //  Sending received messages to all connected clients
    //  Test with the following JavaScript on more than one browser windows:
    //    var wss=new WebSocket("wss://localhost:8080/echo_all");
    //    wss.onmessage=function(evt){console.log(evt.data);};
    //    wss.send("test");
    auto& callbacks_echo_all=server.endpoint["^/echo_all/?$"];
    callbacks_echo_all.onmessage=[&server](Connection& connection) {
        //To receive message from client as string (message_stream.str())
        stringstream message_stream;
        *connection.message >> message_stream.rdbuf();
        
        string response=message_stream.str()+" from "+to_string((size_t)connection.id);
        
        for(auto connection_id: server.get_connection_ids()) {
            stringstream response_stream;
            response_stream << response;
            
            //server.send is an asynchronous function
            server.send(connection_id, response_stream);
        }
    };
    
    //Start WSS-server
    server.start();
    
    return 0;
}
