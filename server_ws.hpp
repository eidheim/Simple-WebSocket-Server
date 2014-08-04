#ifndef SERVER_HTTP_HPP
#define	SERVER_HTTP_HPP

#include "crypto.hpp"

#include <boost/asio.hpp>

#include <regex>
#include <unordered_map>
#include <thread>
#include <mutex>
#include <unordered_set>

#include <iostream>

namespace SimpleWeb {
    struct Connection {
        std::string method, path, http_version;

        std::shared_ptr<std::istream> message;
        size_t message_length;
        
        std::unordered_map<std::string, std::string> header;
        
        std::smatch path_match;
        
        void* id;
    };
    
    class WebSocketCallbacks {
    public:
        std::function<void(Connection&)> onopen;
        std::function<void(Connection&)> onmessage;
        std::function<void(Connection&, const boost::system::error_code&)> onerror;
        std::function<void(Connection&, int)> onclose;
    };

    typedef std::map<std::string, WebSocketCallbacks> endpoint_type;
    
    template <class socket_type>
    class SocketServerBase {
    public:
        endpoint_type endpoint;
        
        SocketServerBase(unsigned short port, size_t num_threads=1) : m_endpoint(boost::asio::ip::tcp::v4(), port), 
            acceptor(m_io_service, m_endpoint), num_threads(num_threads) {}        
        
        void start() {
            accept();
            
            //If num_threads>1, start m_io_service.run() in (num_threads-1) threads for thread-pooling
            for(size_t c=1;c<num_threads;c++) {
                threads.emplace_back([this](){
                    m_io_service.run();
                });
            }

            //Main thread
            m_io_service.run();

            //Wait for the rest of the threads, if any, to finish as well
            for(auto& t: threads) {
                t.join();
            }
        }
        
        //message_header: 129=one fragment, text, 130=one fragment, binary
        //See http://tools.ietf.org/html/rfc6455#section-5.2 for more information
        void send(void* connection_id, std::ostream& stream, const std::function<void(const boost::system::error_code&)>& callback=nullptr, 
                unsigned char message_header=129) const {
            std::shared_ptr<boost::asio::streambuf> write_buffer(new boost::asio::streambuf);
            std::ostream response(write_buffer.get());
            
            stream.seekp(0, std::ios::end);
            size_t length=stream.tellp();
            stream.seekp(0, std::ios::beg);
            
            response.put(message_header);
            //unmasked (first length byte<128)
            if(length>=126) {
                int num_bytes;
                if(length>0xffff) {
                    num_bytes=8;
                    response.put(127);
                }
                else {
                    num_bytes=2;
                    response.put(126);
                }
                
                for(int c=num_bytes-1;c>=0;c--) {
                    response.put((length>>(8*c))%256);
                }
            }
            else
                response.put(length);
            
            response << stream.rdbuf();
            
            //Needs to copy the callback-function in case its destroyed
            boost::asio::async_write(*(socket_type*)connection_id, *write_buffer, 
            [this, write_buffer, callback, connection_id](const boost::system::error_code& ec, size_t bytes_transferred) {
                if(callback) {
                    callback(ec);
                }
            });
        }
        
        std::unordered_set<void*> get_connection_ids() {
            connection_ids_mutex.lock();
            auto copy=connection_ids;
            connection_ids_mutex.unlock();
            return copy;
        }
        
    protected:
        const std::string ws_magic_string="258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        
        std::unordered_set<void*> connection_ids;
        std::mutex connection_ids_mutex;
        
        boost::asio::io_service m_io_service;
        boost::asio::ip::tcp::endpoint m_endpoint;
        boost::asio::ip::tcp::acceptor acceptor;
        size_t num_threads;
        std::vector<std::thread> threads;
        
        virtual void accept() {}

        void process_request_and_start_connection(std::shared_ptr<socket_type> socket) {
            //Create new read_buffer for async_read_until()
            //Shared_ptr is used to pass temporary objects to the asynchronous functions
            std::shared_ptr<boost::asio::streambuf> read_buffer(new boost::asio::streambuf);

            boost::asio::async_read_until(*socket, *read_buffer, "\r\n\r\n",
            [this, socket, read_buffer](const boost::system::error_code& ec, size_t bytes_transferred) {
                if(!ec) {
                    //Convert to istream to extract string-lines
                    std::istream stream(read_buffer.get());

                    std::shared_ptr<Connection> connection(new Connection());
                    *connection=parse_request(stream);
                    
                    start_connection(socket, read_buffer, connection);
                }
            });
        }
        
        Connection parse_request(std::istream& stream) const {
            Connection connection;

            std::regex e("^([^ ]*) ([^ ]*) HTTP/([^ ]*)$");

            std::smatch sm;

            //First parse request method, path, and HTTP-version from the first line
            std::string line;
            getline(stream, line);
            line.pop_back();
            if(std::regex_match(line, sm, e)) {        
                connection.method=sm[1];
                connection.path=sm[2];
                connection.http_version=sm[3];

                bool matched;
                e="^([^:]*): ?(.*)$";
                //Parse the rest of the header
                do {
                    getline(stream, line);
                    line.pop_back();
                    matched=std::regex_match(line, sm, e);
                    if(matched) {
                        connection.header[sm[1]]=sm[2];
                    }

                } while(matched==true);
            }

            return connection;
        }

        bool generate_handshake(std::ostream& handshake, std::shared_ptr<Connection> connection) const {
            if(connection->header.count("Sec-WebSocket-Key")==0)
                return 0;
            
            auto sha1=Crypto<std::string>::SHA1(connection->header["Sec-WebSocket-Key"]+ws_magic_string);

            handshake << "HTTP/1.1 101 Web Socket Protocol Handshake\r\n";
            handshake << "Upgrade: websocket\r\n";
            handshake << "Connection: Upgrade\r\n";
            handshake << "Sec-WebSocket-Accept: " << Crypto<std::string>::Base64::encode(sha1) << "\r\n";
            handshake << "\r\n";
            
            return 1;
        }
        
        void start_connection(std::shared_ptr<socket_type> socket, std::shared_ptr<boost::asio::streambuf> read_buffer, std::shared_ptr<Connection> connection) {
            //Find path- and method-match, and generate response
            for(auto& an_endpoint: endpoint) {
                std::regex e(an_endpoint.first);
                std::smatch path_match;
                if(std::regex_match(connection->path, path_match, e)) {
                    std::shared_ptr<boost::asio::streambuf> write_buffer(new boost::asio::streambuf);
                    std::ostream handshake(write_buffer.get());

                    if(generate_handshake(handshake, connection)) {
                        connection->path_match=std::move(path_match);
                        connection->id=socket.get();
                        //Capture write_buffer in lambda so it is not destroyed before async_write is finished
                        boost::asio::async_write(*socket, *write_buffer, 
                        [this, socket, write_buffer, read_buffer, &an_endpoint, connection](const boost::system::error_code& ec, size_t bytes_transferred) {
                            if(!ec) {
                                connection_open(socket.get(), an_endpoint.second, *connection);
                                read_write_messages(socket, read_buffer, an_endpoint.second, connection);
                            }
                            else
                                connection_error(socket.get(), an_endpoint.second, *connection, ec);
                        });
                    }
                    return;
                }
            }
        }
        
        void read_write_messages(std::shared_ptr<socket_type> socket, std::shared_ptr<boost::asio::streambuf> read_buffer, WebSocketCallbacks& websocketcallbacks, std::shared_ptr<Connection> connection) {
            boost::asio::async_read(*socket, *read_buffer, boost::asio::transfer_exactly(2),
            [this, socket, read_buffer, &websocketcallbacks, connection](const boost::system::error_code& ec, size_t bytes_transferred) {
                if(!ec) {
                    std::istream stream(read_buffer.get());

                    std::vector<unsigned char> num_bytes;
                    num_bytes.resize(2);
                    stream.read((char*)&num_bytes[0], 2);
                    
                    unsigned char opcode=(num_bytes[0]&0x0f);
                    
                    size_t length=(num_bytes[1]&127);

                    if(length==126) {
                        //2 next bytes is the size of content
                        boost::asio::async_read(*socket, *read_buffer, boost::asio::transfer_exactly(2),
                        [this, socket, read_buffer, &websocketcallbacks, connection, opcode](const boost::system::error_code& ec, size_t bytes_transferred) {
                            if(!ec) {
                                std::istream stream(read_buffer.get());
                                
                                std::vector<unsigned char> length_bytes;
                                length_bytes.resize(2);
                                stream.read((char*)&length_bytes[0], 2);
                                
                                size_t length=0;
                                int num_bytes=2;
                                for(int c=0;c<num_bytes;c++)
                                    length+=length_bytes[c]<<(8*(num_bytes-1-c));
                                
                                read_write_message_content(socket, read_buffer, length, websocketcallbacks, connection, opcode);
                            }
                            else
                                connection_error(socket.get(), websocketcallbacks, *connection, ec);
                        });
                    }
                    else if(length==127) {
                        //8 next bytes is the size of content
                        boost::asio::async_read(*socket, *read_buffer, boost::asio::transfer_exactly(8),
                        [this, socket, read_buffer, &websocketcallbacks, connection, opcode](const boost::system::error_code& ec, size_t bytes_transferred) {
                            if(!ec) {
                                std::istream stream(read_buffer.get());
                                
                                std::vector<unsigned char> length_bytes;
                                length_bytes.resize(8);
                                stream.read((char*)&length_bytes[0], 8);
                                
                                size_t length=0;
                                int num_bytes=8;
                                for(int c=0;c<num_bytes;c++)
                                    length+=length_bytes[c]<<(8*(num_bytes-1-c));

                                read_write_message_content(socket, read_buffer, length, websocketcallbacks, connection, opcode);
                            }
                            else
                                connection_error(socket.get(), websocketcallbacks, *connection, ec);
                        });
                    }
                    else
                        read_write_message_content(socket, read_buffer, length, websocketcallbacks, connection, opcode);
                }
                else
                    connection_error(socket.get(), websocketcallbacks, *connection, ec);
            });
        }
        
        void read_write_message_content(std::shared_ptr<socket_type> socket, std::shared_ptr<boost::asio::streambuf> read_buffer, size_t length, 
                WebSocketCallbacks& websocketcallbacks, std::shared_ptr<Connection> connection, unsigned char opcode) {
            boost::asio::async_read(*socket, *read_buffer, boost::asio::transfer_exactly(4+length),
            [this, socket, read_buffer, length, &websocketcallbacks, connection, opcode](const boost::system::error_code& ec, size_t bytes_transferred) {
                if(!ec) {
                    std::istream stream(read_buffer.get());

                    std::vector<unsigned char> mask;
                    mask.resize(4);
                    stream.read((char*)&mask[0], 4);

                    boost::asio::streambuf contentbuf;
                    
                    connection->message=std::shared_ptr<std::istream>(new std::istream(&contentbuf));
                    connection->message_length=length;
                    
                    std::ostream content(&contentbuf);
                    for(size_t c=0;c<length;c++) {
                        content.put(stream.get()^mask[c%4]);
                    }
                    
                    //If connection closed
                    if(opcode==8) {
                        int status=0;
                        if(length==2) {
                            unsigned char byte1=connection->message->get();
                            unsigned char byte2=connection->message->get();
                            status=(byte1<<8)+byte2;
                        }
                                                
                        connection_close(socket.get(), websocketcallbacks, *connection, status);
                        return;
                    }
                    
                    if(websocketcallbacks.onmessage)
                        websocketcallbacks.onmessage(*connection);

                    //Next message
                    read_write_messages(socket, read_buffer, websocketcallbacks, connection);
                }
                else
                    connection_error(socket.get(), websocketcallbacks, *connection, ec);
            });
        }
        
        void connection_open(void* socket, const WebSocketCallbacks& websocketcallbacks, Connection& connection) {
            connection_ids_mutex.lock();
            connection_ids.insert(socket);
            connection_ids_mutex.unlock();
            if(websocketcallbacks.onopen)
                websocketcallbacks.onopen(connection);
        }
        
        void connection_close(void* socket, const WebSocketCallbacks& websocketcallbacks, Connection& connection, int status) {
            //((socket_type*)socket)->shutdown(boost::asio::ip::tcp::socket::shutdown_both);
            //((socket_type*)socket)->close();
            connection_ids_mutex.lock();
            connection_ids.erase(socket);
            connection_ids_mutex.unlock();
            if(websocketcallbacks.onclose)
                websocketcallbacks.onclose(connection, status);
        }
        
        void connection_error(void* socket, const WebSocketCallbacks& websocketcallbacks, Connection& connection, const boost::system::error_code& ec) {
            //((socket_type*)socket)->shutdown(boost::asio::ip::tcp::socket::shutdown_both);
            //((socket_type*)socket)->close();
            connection_ids_mutex.lock();
            connection_ids.erase(socket);
            connection_ids_mutex.unlock();
            if(websocketcallbacks.onerror) {
                boost::system::error_code ec_tmp=ec;
                websocketcallbacks.onerror(connection, ec_tmp);
            }
        }
    };
    
    template<class socket_type>
    class Server : public SocketServerBase<socket_type> {};
    
    typedef boost::asio::ip::tcp::socket WS;
    
    template<>
    class Server<WS> : public SocketServerBase<WS> {
    public:
        Server(unsigned short port, size_t num_threads=1) : SocketServerBase<WS>::SocketServerBase(port, num_threads) {};
        
    private:
        void accept() {
            //Create new socket for this connection
            //Shared_ptr is used to pass temporary objects to the asynchronous functions
            std::shared_ptr<WS> socket(new WS(m_io_service));

            acceptor.async_accept(*socket, [this, socket](const boost::system::error_code& ec) {
                //Immediately start accepting a new connection
                accept();

                if(!ec) {
                    process_request_and_start_connection(socket);
                }
            });
        }
    };
}
#endif	/* SERVER_HTTP_HPP */