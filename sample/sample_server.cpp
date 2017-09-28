#include <string>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <memory>
#include "server_ws.hpp"
typedef SimpleWeb::SocketServer<SimpleWeb::WS> WsServer;

using namespace std;

int main(int, char**)
{
    shared_ptr<WsServer> server;
    thread server_thread;

    cout << "s :  Start server" << endl
        << "t :  sTop server" << endl
        << "m :  send Message to all clients" << endl
        << "q :  Quit" << endl;

    string line;
    while (line != "q")
    {
        getline(cin, line);

        if (line == "s")
        {
            server = make_shared<WsServer>();
            server->config.port = 8081;

            auto& tunnel = server->endpoint["/some/http/resource"];
            tunnel.on_message = [&server](shared_ptr<WsServer::Connection> connection, shared_ptr<WsServer::Message> message)
            {
                auto message_str = message->string();
                cout << "Client Message: " << message_str << endl;

                auto sendThisBack = make_shared<WsServer::SendStream>();
                *sendThisBack << "[echo] " << message_str;
                connection->send(sendThisBack, [](const boost::system::error_code code)
                {
                    if (code)
                    {
                        cout << "Error while responding: " << code << ", error message: " << code.message() << endl;
                    }
                });
            };

            tunnel.on_open = [](shared_ptr<WsServer::Connection> connection)
            {
                cout << "Opened Connection: " << (size_t)connection.get() << " from: " << connection->remote_endpoint_address 
                    <<  ":"  << connection->remote_endpoint_port << endl;
            };

            tunnel.on_close = [](shared_ptr<WsServer::Connection> connection, int status, const string& reason)
            {
                cout << "Closed Connection: " << (size_t)connection.get() << " from: " << connection->remote_endpoint_address 
                    <<  ":"  << connection->remote_endpoint_port << endl;

                //See RFC 6455 7.4.1. for status codes
                cout << "ConnectsTo code: " << status << " Reason: " << reason << endl;
            };

            tunnel.on_error = [](shared_ptr<WsServer::Connection> connection, const boost::system::error_code& code)
            {
                //See http://www.boost.org/doc/libs/1_55_0/doc/html/boost_asio/reference.html, Error Codes for error code meanings
                cout << "Error in connection " << (size_t)connection.get() << ". " << "Error: " << code 
                    << ", error message: " << code.message() << endl;
            };

            server_thread = thread([&server]()
            {
                server->start();
            });
            cout << "Server started" << endl;
        }
        else if (line == "t")
        {
            server->stop();
            server_thread.join();
            server = nullptr;
            cout << "Server stopped" << endl;
        }
        else if (line == "m")
        {
            int i = 0;
            for (auto connection : server->get_connections())
            {
                i++;
                auto msg = make_shared<WsServer::SendStream>();
                *msg << "This is for the kids whippin' up some home-cook, spittin' 86 bars f'n no hook..";
                cout << "sending message...";
                connection->send(msg, [&](const boost::system::error_code code)
                {
                    if (code)
                    {
                        cout << "Error while sending to connnection: " << i << " Code: " << code
                            << " Message: " << code.message() << endl;
                    }
                });
                cout << "sent" << endl;
            }
        }
    }

    if (server != nullptr)
    {
        server->stop();
        server_thread.join();
    }
}
