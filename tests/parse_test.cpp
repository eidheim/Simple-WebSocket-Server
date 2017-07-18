#include "client_ws.hpp"
#include "server_ws.hpp"
#include <cassert>
#include <iostream>

using namespace std;
using namespace SimpleWeb;

class SocketServerTest : public SocketServerBase<WS> {
public:
  SocketServerTest() : SocketServerBase<WS>::SocketServerBase(8080) {}

  void accept() {}

  void parse_request_test() {
    std::shared_ptr<Connection> connection(new Connection(0, *io_service));

    ostream ss(&connection->read_buffer);
    ss << "GET /test/ HTTP/1.1\r\n";
    ss << "TestHeader: test\r\n";
    ss << "TestHeader2:test2\r\n";
    ss << "TestHeader3:test3a\r\n";
    ss << "TestHeader3:test3b\r\n";
    ss << "\r\n";

    connection->parse_handshake();

    assert(connection->method == "GET");
    assert(connection->path == "/test/");
    assert(connection->http_version == "1.1");

    assert(connection->header.size() == 4);
    auto header_it = connection->header.find("TestHeader");
    assert(header_it != connection->header.end() && header_it->second == "test");
    header_it = connection->header.find("TestHeader2");
    assert(header_it != connection->header.end() && header_it->second == "test2");

    header_it = connection->header.find("testheader");
    assert(header_it != connection->header.end() && header_it->second == "test");
    header_it = connection->header.find("testheader2");
    assert(header_it != connection->header.end() && header_it->second == "test2");

    auto range = connection->header.equal_range("testheader3");
    auto first = range.first;
    auto second = first;
    ++second;
    assert(range.first != connection->header.end() && range.second != connection->header.end() &&
           ((first->second == "test3a" && second->second == "test3b") ||
            (first->second == "test3b" && second->second == "test3a")));
  }
};

class SocketClientTest : public SocketClientBase<WS> {
public:
  SocketClientTest(const std::string &server_port_path) : SocketClientBase<WS>::SocketClientBase(server_port_path, 80) {}

  void connect() {}

  void constructor_parse_test1() {
    assert(path == "/test");
    assert(host == "test.org");
    assert(port == 8080);
  }

  void constructor_parse_test2() {
    assert(path == "/test");
    assert(host == "test.org");
    assert(port == 80);
  }

  void constructor_parse_test3() {
    assert(path == "/");
    assert(host == "test.org");
    assert(port == 80);
  }

  void constructor_parse_test4() {
    assert(path == "/");
    assert(host == "test.org");
    assert(port == 8080);
  }

  void parse_response_header_test() {
    auto connection = std::shared_ptr<Connection>(new Connection(*io_service));
    connection->message = std::shared_ptr<Message>(new Message());

    ostream stream(&connection->message->streambuf);
    stream << "HTTP/1.1 200 OK\r\n";
    stream << "TestHeader: test\r\n";
    stream << "TestHeader2:test2\r\n";
    stream << "TestHeader3:test3a\r\n";
    stream << "TestHeader3:test3b\r\n";
    stream << "\r\n";

    connection->parse_handshake();

    assert(connection->header.size() == 4);
    auto header_it = connection->header.find("TestHeader");
    assert(header_it != connection->header.end() && header_it->second == "test");
    header_it = connection->header.find("TestHeader2");
    assert(header_it != connection->header.end() && header_it->second == "test2");

    header_it = connection->header.find("testheader");
    assert(header_it != connection->header.end() && header_it->second == "test");
    header_it = connection->header.find("testheader2");
    assert(header_it != connection->header.end() && header_it->second == "test2");

    auto range = connection->header.equal_range("testheader3");
    auto first = range.first;
    auto second = first;
    ++second;
    assert(range.first != connection->header.end() && range.second != connection->header.end() &&
           ((first->second == "test3a" && second->second == "test3b") ||
            (first->second == "test3b" && second->second == "test3a")));

    connection.reset();
  }
};

int main() {
  assert(case_insensitive_equal("Test", "tesT"));
  assert(case_insensitive_equal("tesT", "test"));
  assert(!case_insensitive_equal("test", "tseT"));
  CaseInsensitiveEqual equal;
  assert(equal("Test", "tesT"));
  assert(equal("tesT", "test"));
  assert(!equal("test", "tset"));
  CaseInsensitiveHash hash;
  assert(hash("Test") == hash("tesT"));
  assert(hash("tesT") == hash("test"));
  assert(hash("test") != hash("tset"));

  SocketServerTest serverTest;
  serverTest.io_service = std::make_shared<asio::io_service>();

  serverTest.parse_request_test();

  SocketClientTest clientTest("test.org:8080/test");
  clientTest.constructor_parse_test1();

  SocketClientTest clientTest2("test.org/test");
  clientTest2.constructor_parse_test2();

  SocketClientTest clientTest3("test.org");
  clientTest3.constructor_parse_test3();

  SocketClientTest clientTest4("test.org:8080");
  clientTest4.io_service = std::make_shared<asio::io_service>();
  clientTest4.constructor_parse_test4();

  clientTest4.parse_response_header_test();
}
