#include "server_wss.hpp"
#include "client_wss.hpp"

using namespace std;

typedef SimpleWeb::SocketServer<SimpleWeb::WSS> WssServer;
typedef SimpleWeb::SocketClient<SimpleWeb::WSS> WssClient;

int main() {
    //WebSocket Secure (WSS)-server at port 8080 using 1 thread
    WssServer server(8080, 1, "server.crt", "server.key");
    
    //Example 1: echo WebSocket Secure endpoint
    //  Added debug messages for example use of the callbacks
    //  Test with the following JavaScript:
    //    var wss=new WebSocket("wss://localhost:8080/echo");
    //    wss.onmessage=function(evt){console.log(evt.data);};
    //    wss.send("test");
    auto& echo=server.endpoint["^/echo/?$"];
    
    echo.onmessage=[&server](shared_ptr<WssServer::Connection> connection, shared_ptr<WssServer::Message> message) {
        //WssServer::Message::string() is a convenience function for:
        //stringstream data_ss;
        //data_ss << message->rdbuf();
        //auto message_str = data_ss.str();
        auto message_str=message->string();
        
        cout << "Server: Message received: \"" << message_str << "\" from " << (size_t)connection.get() << endl;
                
        cout << "Server: Sending message \"" << message_str <<  "\" to " << (size_t)connection.get() << endl;
        
        auto send_stream=make_shared<WssServer::SendStream>();
        *send_stream << message_str;
        //server.send is an asynchronous function
        server.send(connection, send_stream, [](const boost::system::error_code& ec){
            if(ec) {
                cout << "Server: Error sending message. " <<
                //See http://www.boost.org/doc/libs/1_55_0/doc/html/boost_asio/reference.html, Error Codes for error code meanings
                        "Error: " << ec << ", error message: " << ec.message() << endl;
            }
        });
    };
    
    echo.onopen=[](shared_ptr<WssServer::Connection> connection) {
        cout << "Server: Opened connection " << (size_t)connection.get() << endl;
    };
    
    //See RFC 6455 7.4.1. for status codes
    echo.onclose=[](shared_ptr<WssServer::Connection> connection, int status, const string& /*reason*/) {
        cout << "Server: Closed connection " << (size_t)connection.get() << " with status code " << status << endl;
    };
    
    //See http://www.boost.org/doc/libs/1_55_0/doc/html/boost_asio/reference.html, Error Codes for error code meanings
    echo.onerror=[](shared_ptr<WssServer::Connection> connection, const boost::system::error_code& ec) {
        cout << "Server: Error in connection " << (size_t)connection.get() << ". " << 
                "Error: " << ec << ", error message: " << ec.message() << endl;
    };
    
    //Example 2: Echo thrice
    //  Send a received message three times back to the client
    //  Test with the following JavaScript:
    //    var wss=new WebSocket("wss://localhost:8080/echo_thrice");
    //    wss.onmessage=function(evt){console.log(evt.data);};
    //    wss.send("test");
    auto& echo_thrice=server.endpoint["^/echo_thrice/?$"];
    echo_thrice.onmessage=[&server](shared_ptr<WssServer::Connection> connection, shared_ptr<WssServer::Message> message) {
        auto message_str=message->string();
        
        auto send_stream1=make_shared<WssServer::SendStream>();
        *send_stream1 << message_str;
        //server.send is an asynchronous function
        server.send(connection, send_stream1, [&server, connection, message_str](const boost::system::error_code& ec) {
            if(!ec) {
                auto send_stream3=make_shared<WssServer::SendStream>();
                *send_stream3 << message_str;
                server.send(connection, send_stream3); //Sent after send_stream1 is sent, and most likely after send_stream2
            }
        });
        //Do not reuse send_stream1 here as it most likely is not sent yet
        auto send_stream2=make_shared<WssServer::SendStream>();
        *send_stream2 << message_str;
        server.send(connection, send_stream2); //Most likely queued, and sent after send_stream1
    };

    //Example 3: Echo to all WebSocket Secure endpoints
    //  Sending received messages to all connected clients
    //  Test with the following JavaScript on more than one browser windows:
    //    var wss=new WebSocket("wss://localhost:8080/echo_all");
    //    wss.onmessage=function(evt){console.log(evt.data);};
    //    wss.send("test");
    auto& echo_all=server.endpoint["^/echo_all/?$"];
    echo_all.onmessage=[&server](shared_ptr<WssServer::Connection> /*connection*/, shared_ptr<WssServer::Message> message) {
        auto message_str=message->string();
        
        //echo_all.get_connections() can also be used to solely receive connections on this endpoint
        for(auto a_connection: server.get_connections()) {
            auto send_stream=make_shared<WssServer::SendStream>();
            *send_stream << message_str;
            
            //server.send is an asynchronous function
            server.send(a_connection, send_stream);
        }
    };
    
    thread server_thread([&server](){
        //Start WSS-server
        server.start();
    });
    
    //Wait for server to start so that the client can connect
    this_thread::sleep_for(chrono::seconds(1));
    
    //Example 4: Client communication with server
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
    WssClient client("localhost:8080/echo", false);
    client.onmessage=[&client](shared_ptr<WssClient::Message> message) {
        auto message_str=message->string();
        
        cout << "Client: Message received: \"" << message_str << "\"" << endl;
        
        cout << "Client: Sending close connection" << endl;
        client.send_close(1000);
    };
    
    client.onopen=[&client]() {
        cout << "Client: Opened connection" << endl;
        
        string message="Hello";
        cout << "Client: Sending message: \"" << message << "\"" << endl;

        auto send_stream=make_shared<WssClient::SendStream>();
        *send_stream << message;
        client.send(send_stream);
    };
    
    client.onclose=[](int status, const string& /*reason*/) {
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
