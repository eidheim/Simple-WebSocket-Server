#include "server_wss.hpp"
#include "client_wss.hpp"

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
    auto& echo=server.endpoint["^/echo/?$"];
    
    //C++14, lambda parameters declared with auto
    //For C++11 use: (shared_ptr<Server<WSS>::Connection> connection, shared_ptr<Server<WSS>::Message> message)
    echo.onmessage=[&server](auto connection, auto message) {
        //To receive message from client as string (message_stream.str())
        stringstream data_ss;
        message->data >> data_ss.rdbuf();
        
        cout << "Server: Message received: \"" << data_ss.str() << "\" from " << (size_t)connection.get() << endl;
                
        cout << "Server: Sending message \"" << data_ss.str() <<  "\" to " << (size_t)connection.get() << endl;
        
        //server.send is an asynchronous function
        server.send(connection, data_ss, [](const boost::system::error_code& ec){
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
    echo.onclose=[](auto connection, int status, const string& reason) {
        cout << "Server: Closed connection " << (size_t)connection.get() << " with status code " << status << endl;
    };
    
    //See http://www.boost.org/doc/libs/1_55_0/doc/html/boost_asio/reference.html, Error Codes for error code meanings
    echo.onerror=[](auto connection, const boost::system::error_code& ec) {
        cout << "Server: Error in connection " << (size_t)connection.get() << ". " << 
                "Error: " << ec << ", error message: " << ec.message() << endl;
    };
    

    //Example 2: Echo to all WebSocket Secure endpoints
    //  Sending received messages to all connected clients
    //  Test with the following JavaScript on more than one browser windows:
    //    var wss=new WebSocket("wss://localhost:8080/echo_all");
    //    wss.onmessage=function(evt){console.log(evt.data);};
    //    wss.send("test");
    auto& echo_all=server.endpoint["^/echo_all/?$"];
    echo_all.onmessage=[&server](auto connection, auto message) {
        //To receive message from client as string (message_stream.str())
        stringstream data_ss;
        message->data >> data_ss.rdbuf();
        
        for(auto a_connection: server.get_connections()) {
            stringstream response_ss;
            response_ss << data_ss.str();
            
            //server.send is an asynchronous function
            server.send(a_connection, response_ss);
        }
    };
    
    thread server_thread([&server](){
        //Start WSS-server
        server.start();
    });
    
    //Wait for server to start so that the client can connect
    this_thread::sleep_for(chrono::seconds(1));
    
    //Example 3: Client communication with server
    //Second Client() parameter set to false: no certificate verification
    //Possible output:
    //Server: Opened connection 140184920260656
    //Client: Opened connection
    //Client: Sending message: "Hello"
    //Server: Message received: "Hello" from 140184920260656
    //Server: Sending message "Hello" to 140184920260656
    //Client: Message received: "Hello"
    //Client: Sending close connection
    //Server: Closed connection 140184920260656 with status code 1000
    //Client: Closed connection with status code 1000
    Client<WSS> client("localhost:8080/echo", false);
    client.onmessage=[&client](auto message) {    
        stringstream data_ss;
        data_ss << message->data.rdbuf();
        cout << "Client: Message received: \"" << data_ss.str() << "\"" << endl;
        
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
    
    client.onclose=[](int status, const string& reason) {
        cout << "Client: Closed connection with status code " << status << endl;
    };
    
    //See http://www.boost.org/doc/libs/1_55_0/doc/html/boost_asio/reference.html, Error Codes for error code meanings
    client.onerror=[](const boost::system::error_code& ec) {
        cout << "Client: Error: " << ec << ", error message: " << ec.message() << endl;
    };
    
    client.start();
    
    server_thread.join();
    
    return 0;
}