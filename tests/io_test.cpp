#include "server_ws.hpp"
#include "client_ws.hpp"

#include <cassert>

using namespace std;

typedef SimpleWeb::SocketServer<SimpleWeb::WS> WsServer;
typedef SimpleWeb::SocketClient<SimpleWeb::WS> WsClient;

int main() {
    WsServer server(8080, 4);
    
    auto& echo=server.endpoint["^/echo/?$"];
    
    atomic<int> server_callback_count(0);
    
    echo.onmessage=[&server, &server_callback_count](shared_ptr<WsServer::Connection> connection, shared_ptr<WsServer::Message> message) {
        auto message_str=message->string();
        assert(message_str=="Hello");
        
        ++server_callback_count;
        auto send_stream=make_shared<WsServer::SendStream>();
        *send_stream << message_str;
        server.send(connection, send_stream, [](const boost::system::error_code& ec){
            if(ec) {
                cerr << ec.message() << endl;
                assert(false);
            }
        });
    };
    
    echo.onopen=[&server_callback_count](shared_ptr<WsServer::Connection> /*connection*/) {
        ++server_callback_count;
    };
    
    echo.onclose=[&server_callback_count](shared_ptr<WsServer::Connection> /*connection*/, int /*status*/, const string& /*reason*/) {
        ++server_callback_count;
    };
    
    echo.onerror=[](shared_ptr<WsServer::Connection> /*connection*/, const boost::system::error_code& ec) {
        cerr << ec.message() << endl;
        assert(false);
    };
    
    auto& echo_thrice=server.endpoint["^/echo_thrice/?$"];
    echo_thrice.onmessage=[&server](shared_ptr<WsServer::Connection> connection, shared_ptr<WsServer::Message> message) {
        auto message_str=message->string();
        
        auto send_stream1=make_shared<WsServer::SendStream>();
        *send_stream1 << message_str;
        server.send(connection, send_stream1, [&server, connection, message_str](const boost::system::error_code& ec) {
            if(!ec) {
                auto send_stream3=make_shared<WsServer::SendStream>();
                *send_stream3 << message_str;
                server.send(connection, send_stream3); //Sent after send_stream1 is sent, and most likely after send_stream2
            }
        });
        //Do not reuse send_stream1 here as it most likely is not sent yet
        auto send_stream2=make_shared<WsServer::SendStream>();
        *send_stream2 << message_str;
        server.send(connection, send_stream2); //Most likely queued, and sent after send_stream1
    };
    
    thread server_thread([&server](){
        server.start();
    });
    
    this_thread::sleep_for(chrono::seconds(1));
    
    {
        WsClient client("localhost:8080/echo");
        
        atomic<int> client_callback_count(0);
        
        client.onmessage=[&client, &client_callback_count](shared_ptr<WsClient::Message> message) {
            assert(message->string()=="Hello");
            
            ++client_callback_count;
            
            client.send_close(1000);
        };
        
        client.onopen=[&client, &client_callback_count]() {
            ++client_callback_count;
            
            auto send_stream=make_shared<WsClient::SendStream>();
            *send_stream << "Hello";
            client.send(send_stream);
        };
        
        client.onclose=[&client_callback_count](int /*status*/, const string& /*reason*/) {
            ++client_callback_count;
        };
        
        client.onerror=[](const boost::system::error_code& ec) {
            cerr << ec.message() << endl;
            assert(false);
        };
        
        thread client_thread([&client](){
            client.start();
        });
        
        this_thread::sleep_for(chrono::seconds(1));
        
        client.stop();
        client_thread.join();
        
        assert(client_callback_count==3);
    }
    
    {
        WsClient client("localhost:8080/echo_thrice");
        
        atomic<int> client_callback_count(0);
        
        client.onmessage=[&client, &client_callback_count](shared_ptr<WsClient::Message> message) {
            assert(message->string()=="Hello");
            
            ++client_callback_count;
            
            client.send_close(1000);
        };
        
        client.onopen=[&client, &client_callback_count]() {
            ++client_callback_count;
            
            auto send_stream=make_shared<WsClient::SendStream>();
            *send_stream << "Hello";
            client.send(send_stream);
        };
        
        client.onclose=[&client_callback_count](int /*status*/, const string& /*reason*/) {
            ++client_callback_count;
        };
        
        client.onerror=[](const boost::system::error_code& ec) {
            cerr << ec.message() << endl;
            assert(false);
        };
        
        thread client_thread([&client](){
            client.start();
        });
        
        this_thread::sleep_for(chrono::seconds(1));
        
        client.stop();
        client_thread.join();
        
        assert(client_callback_count==5);
    }
    
    server.stop();
    server_thread.join();
    
    assert(server_callback_count==3);
    
    return 0;
}
