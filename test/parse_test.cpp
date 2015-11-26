#include "server_ws.hpp"
#include "client_ws.hpp"
#include <iostream>

using namespace std;
using namespace SimpleWeb;

class SocketServerTest : public SocketServerBase<WS> {
public:
    SocketServerTest() : 
            SocketServerBase<WS>::SocketServerBase(8080, 1, 5, 300) {}
            
    void accept() {}
    
    bool parse_request_test() {
        std::shared_ptr<Connection> connection(new Connection(new WS(io_service)));
        
        stringstream ss;
        ss << "GET /test/ HTTP/1.1\r\n";
        ss << "TestHeader: test\r\n";
        ss << "TestHeader2:test2\r\n";
        ss << "\r\n";
        
        parse_handshake(connection, ss);
        
        if(connection->method!="GET")
            return 0;
        if(connection->path!="/test/")
            return 0;
        if(connection->http_version!="1.1")
            return 0;
        
        if(connection->header.size()!=2)
            return 0;
        if(connection->header.count("TestHeader")==0)
            return 0;
        if(connection->header["TestHeader"]!="test")
            return 0;

        if(connection->header.count("TestHeader2")==0)
            return 0;
        if(connection->header["TestHeader2"]!="test2")
            return 0;
        
        return 1;
    }
};

class SocketClientTest : public SocketClientBase<WS> {
public:
    SocketClientTest(const std::string& server_port_path) : SocketClientBase<WS>::SocketClientBase(server_port_path, 80) {}
    
    void connect() {}
    
    bool constructor_parse_test1() {
        if(path!="/test")
            return 0;
        if(host!="test.org")
            return 0;
        if(port!=8080)
            return 0;
        
        return 1;
    }
    
    bool constructor_parse_test2() {
        if(path!="/test")
            return 0;
        if(host!="test.org")
            return 0;
        if(port!=80)
            return 0;
        
        return 1;
    }
    
    bool constructor_parse_test3() {
        if(path!="/")
            return 0;
        if(host!="test.org")
            return 0;
        if(port!=80)
            return 0;
        
        return 1;
    }
    
    bool constructor_parse_test4() {
        if(path!="/")
            return 0;
        if(host!="test.org")
            return 0;
        if(port!=8080)
            return 0;
        
        return 1;
    }
    
    bool parse_response_header_test() {
        connection=std::unique_ptr<Connection>(new Connection(new WS(io_service)));
        
        stringstream ss;
        ss << "HTTP/1.1 200 OK\r\n";
        ss << "TestHeader: test\r\n";
        ss << "TestHeader2:test2\r\n";
        ss << "\r\n";
        
        parse_handshake(ss);
                
        if(connection->header.size()!=2)
            return 0;
        if(connection->header.count("TestHeader")==0)
            return 0;
        if(connection->header["TestHeader"]!="test")
            return 0;

        if(connection->header.count("TestHeader2")==0)
            return 0;
        if(connection->header["TestHeader2"]!="test2")
            return 0;
        
        connection.reset();
        return 1;
    }
};

int main(int argc, char** argv) {
    SocketServerTest serverTest;
    if(!serverTest.parse_request_test()) {
        cerr << "FAIL SocketServer::parse_request" << endl;
        return 1;
    }
    
    SocketClientTest clientTest("test.org:8080/test");
    if(!clientTest.constructor_parse_test1()) {
        cerr << "FAIL SocketClient::SocketClient" << endl;
        return 1;
    }
    
    SocketClientTest clientTest2("test.org/test");
    if(!clientTest2.constructor_parse_test2()) {
        cerr << "FAIL SocketClient::SocketClient" << endl;
        return 1;
    }
    
    SocketClientTest clientTest3("test.org");
    if(!clientTest3.constructor_parse_test3()) {
        cerr << "FAIL SocketClient::SocketClient" << endl;
        return 1;
    }
    
    SocketClientTest clientTest4("test.org:8080");
    if(!clientTest4.constructor_parse_test4()) {
        cerr << "FAIL SocketClient::SocketClient" << endl;
        return 1;
    }
    
    if(!clientTest4.parse_response_header_test()) {
        cerr << "FAIL SocketClient::parse_response_header" << endl;
        return 1;
    }
    
    return 0;
}
