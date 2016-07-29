#include <iostream>
#include <string>

#include <client_ws.hpp>
#include <server_ws.hpp>

using std::cout;
using std::endl;
using std::string;

typedef SimpleWeb::SocketServer<SimpleWeb::WS> WsServer;
typedef SimpleWeb::SocketClient<SimpleWeb::WS> WsClient;
void simpleEchoServer(WsServer &server) {
  //Example 1: echo WebSocket endpoint
  //  Added debug messages for example use of the callbacks
  //  Test with the following JavaScript:
  //    var ws=new WebSocket("ws://localhost:8080/echo");
  //    ws.onmessage=function(evt){console.log(evt.data);};
  //    ws.send("test");
  auto& echo=server.endpoint["^/echo/?$"];

  echo.onmessage=[&server](std::shared_ptr<WsServer::Connection> connection, std::shared_ptr<WsServer::Message> message) {
      //WsServer::Message::string() is a convenience function for:
      //stringstream data_ss;
      //data_ss << message->rdbuf();
      //auto message_str = data_ss.str();
      auto message_str=message->string();

      // cout << "Server: Message received: \"" << message_str << "\" from " << (size_t)connection.get() << endl;
      //
      // cout << "Server: Sending message \"" << message_str <<  "\" to " << (size_t)connection.get() << endl;

      auto send_stream=std::make_shared<WsServer::SendStream>();
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

  echo.onopen=[](std::shared_ptr<WsServer::Connection> connection) {
      cout << "Server: Opened connection " << (size_t)connection.get() << endl;
  };

  //See RFC 6455 7.4.1. for status codes
  echo.onclose=[&server](std::shared_ptr<WsServer::Connection> connection, int status, const string& /*reason*/) {
      cout << "Server: Closed connection " << (size_t)connection.get() << " with status code " << status << endl;
      server.stop();
  };

  //See http://www.boost.org/doc/libs/1_55_0/doc/html/boost_asio/reference.html, Error Codes for error code meanings
  echo.onerror=[](std::shared_ptr<WsServer::Connection> connection, const boost::system::error_code& ec) {
      cout << "Server: Error in connection " << (size_t)connection.get() << ". " <<
              "Error: " << ec << ", error message: " << ec.message() << endl;
  };
}

void simpleEchoClient(WsServer &server) {
  WsClient client("localhost:8080/echo");
  ssize_t count = 10000;
  auto start = std::chrono::steady_clock::now();
  client.onmessage=[&client, &server, &count, &start](std::shared_ptr<WsClient::Message> message) {
      auto message_str=message->string();
      //cout << "Client: Message received: \"" << message_str << "\"" << endl;
      if (--count < 0) {
        cout << "Client: Sending close connection" << endl;
        client.send_close(1000);
        auto took = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-start);
        cout << "10000 took " << took.count() << "msec" << endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        //server.stop();
      } else {
          string message="Hello";
          //cout << "Client: Sending message: \"" << message << "\"" << endl;
          auto send_stream=std::make_shared<WsClient::SendStream>();
          *send_stream << message;
          client.send(send_stream);
      }
  };

  client.onopen=[&client]() {
      cout << "Client: Opened connection" << endl;
      string message="Hello";
      //cout << "Client: Sending message: \"" << message << "\"" << endl;
      auto send_stream=std::make_shared<WsClient::SendStream>();
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
}

int main() {
  WsServer server(8080, 4);
  simpleEchoServer(server);
  std::thread server_thread([&server](){
     //Start WS-server
     server.start();
  });
  std::this_thread::sleep_for(std::chrono::milliseconds(500));

  simpleEchoClient(server);

  server_thread.join();
}
