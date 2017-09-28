#include <string>
#include <iostream>
#include <iomanip>
#include "boost/thread.hpp"
#include "client_ws.hpp"
typedef SimpleWeb::SocketClient<SimpleWeb::WS> WsClient;

using namespace std;

int main(int, char**)
{
    shared_ptr<WsClient> client;
    shared_ptr<WsClient::Connection> _connection;
    boost::thread client_thread;

    cout << "s :  Set up connection" << endl
        << "l :  cLose connection" << endl
        << "c :  stop Client" << endl
        << "m :  send Message" << endl
        << "q :  Quit" << endl;

    string line;
    while (line != "q")
    {
        getline(cin, line);

        if (line == "s")
        {
            client = std::make_shared<WsClient>("localhost:8081/some/http/resource");


            client->SetProtocol("some-protocol");  // optional

            client->on_open = [&](shared_ptr<WsClient::Connection> connection)
            {
                _connection = connection;
                cout << "Client Started & Connection " << (size_t)connection.get() << " Opened" << endl << endl;
            };

            client->on_close = [&](shared_ptr<WsClient::Connection> connection, int code, const string& reason)
            {
                _connection = nullptr;
                cout << "Closed Connection " << (size_t)connection.get() << "(" << code << ")" << endl << "    Reason: " << reason << endl << endl;
            };

            client->on_error = [](shared_ptr<WsClient::Connection> connection, const boost::system::error_code& code)
            {
                cout << "Error in Connection " << (size_t)connection.get() << "(" << code << ")" << endl << "    Code: " << code.message() << endl << endl;
            };

            client->on_message = [](shared_ptr<WsClient::Connection> connection, shared_ptr<WsClient::Message> message)
            {
                cout << "Server Message on Connection " << (size_t)connection.get() <<  endl << "   Message: " << message->string() << endl << endl;
            };

            client_thread = boost::thread([&client]()
            {
                client->start();
            });
            cout << "Connection started" << endl << endl;
        }
        else if (line == "c")
        {
            if (client != nullptr)
            {
                client->stop();
                client = nullptr;
                cout << "Stopped Client" << endl << endl;
            }
            else
            {
                cout << "Client Already Stopped" << endl << endl;
            }

        }
        else if (line == "l")
        {
            if (_connection != nullptr)
            {
                _connection->send_close(10, "Word to your moms, I came to drop bombs, I got more rhymes than the bible's got psalms.", [](const boost::system::error_code code)
                {
                    cout << "Error on send_close Code: " << code
                        << " Message: " << code.message() << endl;
                });
                cout << "Closed connection " << (size_t)_connection.get() << " with message" << endl << endl;
            }
            else
            {
                cout << "Connection already closed" << endl << endl;
            }
        }

        else if (line == "m")
        {
            auto msg = std::make_shared<WsClient::SendStream>();
            *msg << "It's tricky to rock a rhyme to rock a rhyme that's right on time it's tricky!";
            _connection->send(msg);
            cout << "Message sent" << endl << endl;
        }
    }
    if (client != nullptr)
    {
        client->stop();
        client_thread.join();
    }
}
