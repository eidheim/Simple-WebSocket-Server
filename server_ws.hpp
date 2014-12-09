#ifndef SERVER_WS_HPP
#define	SERVER_WS_HPP

#include "crypto.hpp"

#include <boost/asio.hpp>

#include <regex>
#include <unordered_map>
#include <thread>
#include <mutex>
#include <set>
#include <memory>

#include <iostream>
#include <fstream>

namespace SimpleWeb {
    template <class socket_type>
    class SocketServer;
        
    template <class socket_type>
    class SocketServerBase {
    public:
        class Connection {
            friend class SocketServerBase<socket_type>;;
            friend class SocketServer<socket_type>;
            
        public:
            std::string method, path, http_version;

            std::unordered_map<std::string, std::string> header;

            std::smatch path_match;
            
            boost::asio::ip::address remote_endpoint_address;
            unsigned short remote_endpoint_port;
            
        private:
            //boost::asio::ssl::stream constructor needs move, until then we store socket as unique_ptr
            std::unique_ptr<socket_type> socket;
            
            std::atomic<bool> closed;

            std::unique_ptr<boost::asio::deadline_timer> timer_idle;

            Connection(socket_type* socket_ptr): socket(socket_ptr), closed(false) {}
            
            void read_remote_endpoint_data() {
                try {
                    remote_endpoint_address=socket->lowest_layer().remote_endpoint().address();
                    remote_endpoint_port=socket->lowest_layer().remote_endpoint().port();
                }
                catch(const std::exception& e) {
                    std::cerr << e.what() << std::endl;
                }
            }
        };
        
        class Message {
            friend class SocketServerBase<socket_type>;
            
        public:
            std::istream data;
            size_t length;
            unsigned char fin_rsv_opcode;
            
        private:
            Message(): data(&data_buffer) {}
            boost::asio::streambuf data_buffer;
        };
        
        struct Callbacks {
            std::function<void(std::shared_ptr<Connection>)> onopen;
            std::function<void(std::shared_ptr<Connection>, std::shared_ptr<Message>)> onmessage;
            std::function<void(std::shared_ptr<Connection>, const boost::system::error_code&)> onerror;
            std::function<void(std::shared_ptr<Connection>, int, const std::string&)> onclose;
        };
        
        std::map<std::string, Callbacks> endpoint;        
        
        void start() {
            accept();
            
            //If num_threads>1, start m_io_service.run() in (num_threads-1) threads for thread-pooling
            for(size_t c=1;c<num_threads;c++) {
                threads.emplace_back([this](){
                    asio_io_service.run();
                });
            }

            //Main thread
            asio_io_service.run();

            //Wait for the rest of the threads, if any, to finish as well
            for(auto& t: threads) {
                t.join();
            }
        }
        
        void stop() {
            asio_io_service.stop();
        }
        
        //fin_rsv_opcode: 129=one fragment, text, 130=one fragment, binary, 136=close connection
        //See http://tools.ietf.org/html/rfc6455#section-5.2 for more information
        void send(std::shared_ptr<Connection> connection, std::ostream& stream, 
                const std::function<void(const boost::system::error_code&)>& callback=nullptr, 
                unsigned char fin_rsv_opcode=129) {
            if(fin_rsv_opcode!=136)
                timer_idle_reset(connection);
            std::shared_ptr<boost::asio::streambuf> write_buffer(new boost::asio::streambuf);
            std::ostream response(write_buffer.get());
            
            stream.seekp(0, std::ios::end);
            size_t length=stream.tellp();
            stream.seekp(0, std::ios::beg);
            
            response.put(fin_rsv_opcode);
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
            
            //Need to copy the callback-function in case its destroyed
            boost::asio::async_write(*connection->socket, *write_buffer, 
                    [this, connection, write_buffer, callback]
                    (const boost::system::error_code& ec, size_t bytes_transferred) {
                if(callback) {
                    callback(ec);
                }
            });
        }
        
        void send_close(std::shared_ptr<Connection> connection, int status, const std::string& reason="") {
            //Send close only once (in case close is initiated by server)
            if(connection->closed.load()) {
                return;
            }
            connection->closed.store(true);
            
            std::stringstream response;
            
            response.put(status>>8);
            response.put(status%256);
            
            response << reason;

            //fin_rsv_opcode=136: message close
            send(connection, response, [](const boost::system::error_code& ec){}, 136);
        }
        
        std::set<std::shared_ptr<Connection> > get_connections() {
            connections_mutex.lock();
            auto copy=connections;
            connections_mutex.unlock();
            return copy;
        }
        
    protected:
        const std::string ws_magic_string="258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        
        std::set<std::shared_ptr<Connection> > connections;
        std::mutex connections_mutex;
        
        boost::asio::io_service asio_io_service;
        boost::asio::ip::tcp::endpoint asio_endpoint;
        boost::asio::ip::tcp::acceptor asio_acceptor;
        size_t num_threads;
        std::vector<std::thread> threads;
        
        size_t timeout_request;
        size_t timeout_idle;
        
        std::string document_root;

        SocketServerBase(unsigned short port, size_t num_threads, size_t timeout_request, size_t timeout_idle, std::string document_root) :
                asio_endpoint(boost::asio::ip::tcp::v4(), port), asio_acceptor(asio_io_service, asio_endpoint), num_threads(num_threads),
                timeout_request(timeout_request), timeout_idle(timeout_idle), document_root(document_root) {
            if (!document_root.empty()) {
                char buffer[PATH_MAX];
                char *real_path = realpath(document_root.c_str(), buffer);
                if (real_path)
                    this->document_root = real_path;
                else
                    this->document_root.clear();
            }
        }
        
        virtual void accept()=0;
        
        std::shared_ptr<boost::asio::deadline_timer> set_timeout_on_connection(std::shared_ptr<Connection> connection, size_t seconds) {
            std::shared_ptr<boost::asio::deadline_timer> timer(new boost::asio::deadline_timer(asio_io_service));
            timer->expires_from_now(boost::posix_time::seconds(seconds));
            timer->async_wait([connection](const boost::system::error_code& ec){
                if(!ec) {
                    connection->socket->lowest_layer().shutdown(boost::asio::ip::tcp::socket::shutdown_both);
                    connection->socket->lowest_layer().close();
                }
            });
            return timer;
        }

        void read_handshake(std::shared_ptr<Connection> connection) {
            connection->read_remote_endpoint_data();
            
            //Create new read_buffer for async_read_until()
            //Shared_ptr is used to pass temporary objects to the asynchronous functions
            std::shared_ptr<boost::asio::streambuf> read_buffer(new boost::asio::streambuf);

            //Set timeout on the following boost::asio::async-read or write function
            std::shared_ptr<boost::asio::deadline_timer> timer;
            if(timeout_request>0)
                timer=set_timeout_on_connection(connection, timeout_request);
            
            boost::asio::async_read_until(*connection->socket, *read_buffer, "\r\n\r\n",
                    [this, connection, read_buffer, timer]
                    (const boost::system::error_code& ec, size_t bytes_transferred) {
                if(timeout_request>0)
                    timer->cancel();
                if(!ec) {
                    //Convert to istream to extract string-lines
                    std::istream stream(read_buffer.get());

                    parse_handshake(connection, stream);
                    
                    write_handshake(connection, read_buffer);
                }
            });
        }
        
        void parse_handshake(std::shared_ptr<Connection> connection, std::istream& stream) const {
            std::regex e("^([^ ]*) ([^ ]*) HTTP/([^ ]*)$");

            std::smatch sm;

            //First parse request method, path, and HTTP-version from the first line
            std::string line;
            getline(stream, line);
            line.pop_back();
            if(std::regex_match(line, sm, e)) {        
                connection->method=sm[1];
                connection->path=sm[2];
                connection->http_version=sm[3];

                bool matched;
                e="^([^:]*): ?(.*)$";
                //Parse the rest of the header
                do {
                    getline(stream, line);
                    line.pop_back();
                    matched=std::regex_match(line, sm, e);
                    if(matched) {
                        connection->header[sm[1]]=sm[2];
                    }

                } while(matched==true);
            }
        }
        
        void write_handshake(std::shared_ptr<Connection> connection, std::shared_ptr<boost::asio::streambuf> read_buffer) {
            //Find path- and method-match, and generate response
            for(auto& an_endpoint: endpoint) {
                std::regex e(an_endpoint.first);
                std::smatch path_match;
                if(std::regex_match(connection->path, path_match, e)) {
                    std::shared_ptr<boost::asio::streambuf> write_buffer(new boost::asio::streambuf);
                    std::ostream handshake(write_buffer.get());

                    if(generate_handshake(connection, handshake)) {
                        connection->path_match=std::move(path_match);
                        //Capture write_buffer in lambda so it is not destroyed before async_write is finished
                        boost::asio::async_write(*connection->socket, *write_buffer, 
                                [this, connection, write_buffer, read_buffer, &an_endpoint]
                                (const boost::system::error_code& ec, size_t bytes_transferred) {
                            if(!ec) {
                                connection_open(connection, an_endpoint.second);
                                read_message(connection, read_buffer, an_endpoint.second);
                            }
                            else
                                connection_error(connection, an_endpoint.second, ec);
                        });
                    }
                    return;
                }
            }

            // if matched nothing and document_root was setted then try send file
            if (document_root.empty())
                return;

            std::string filename = document_root + (connection->path == "/" ? "/index.html" : connection->path);
            std::shared_ptr<boost::asio::streambuf> write_buffer(new boost::asio::streambuf);
            std::ostream response(write_buffer.get());


            char real_filename_buffer[PATH_MAX];
            char* res_real_filename = realpath(filename.c_str(), real_filename_buffer);

            std::string real_filename = "";
            if (res_real_filename)
                real_filename = real_filename_buffer;

            struct stat st;
            lstat(real_filename.c_str(), &st);

            std::ifstream ifs;
            if (res_real_filename && real_filename.find(document_root) == 0 && S_ISREG(st.st_mode))
                ifs.open(real_filename, std::ifstream::in);
            else
                ifs.close();

            if(ifs) {
                ifs.seekg(0, std::ios::end);
                size_t length=ifs.tellg();
                ifs.seekg(0, std::ios::beg);
                response << "HTTP/1.1 200 OK\r\nContent-Length: " << length << "\r\n\r\n" << ifs.rdbuf();
                ifs.close();
            }
            else {
                response << "HTTP/1.1 404 Not found\r\nContent-Length: 59\r\n\r\n<!DOCTYPE html><html><body><h1>Not found</h1></body></html>";
            }

            boost::asio::async_write(*connection->socket, *write_buffer, [this, connection, write_buffer](const boost::system::error_code& ec, size_t bytes_transferred) {});
        }
        
        bool generate_handshake(std::shared_ptr<Connection> connection, std::ostream& handshake) const {
            if(connection->header.count("Sec-WebSocket-Key")==0)
                return 0;
            
            auto sha1=Crypto::SHA1(connection->header["Sec-WebSocket-Key"]+ws_magic_string);

            handshake << "HTTP/1.1 101 Web Socket Protocol Handshake\r\n";
            handshake << "Upgrade: websocket\r\n";
            handshake << "Connection: Upgrade\r\n";
            handshake << "Sec-WebSocket-Accept: " << Crypto::Base64::encode(sha1) << "\r\n";
            handshake << "\r\n";
            
            return 1;
        }
        
        void read_message(std::shared_ptr<Connection> connection, 
                std::shared_ptr<boost::asio::streambuf> read_buffer, Callbacks& callbacks) {
            boost::asio::async_read(*connection->socket, *read_buffer, boost::asio::transfer_exactly(2),
                    [this, connection, read_buffer, &callbacks]
                    (const boost::system::error_code& ec, size_t bytes_transferred) {
                if(!ec) {
                    std::istream stream(read_buffer.get());

                    std::vector<unsigned char> first_bytes;
                    first_bytes.resize(2);
                    stream.read((char*)&first_bytes[0], 2);
                    
                    unsigned char fin_rsv_opcode=first_bytes[0];
                    
                    //Close connection if unmasked message from client (protocol error)
                    if(first_bytes[1]<128) {
                        const std::string reason="message from client not masked";
                        send_close(connection, 1002, reason);
                        connection_close(connection, callbacks, 1002, reason);
                        return;
                    }
                    
                    size_t length=(first_bytes[1]&127);

                    if(length==126) {
                        //2 next bytes is the size of content
                        boost::asio::async_read(*connection->socket, *read_buffer, boost::asio::transfer_exactly(2),
                                [this, connection, read_buffer, &callbacks, fin_rsv_opcode]
                                (const boost::system::error_code& ec, size_t bytes_transferred) {
                            if(!ec) {
                                std::istream stream(read_buffer.get());
                                
                                std::vector<unsigned char> length_bytes;
                                length_bytes.resize(2);
                                stream.read((char*)&length_bytes[0], 2);
                                
                                size_t length=0;
                                int num_bytes=2;
                                for(int c=0;c<num_bytes;c++)
                                    length+=length_bytes[c]<<(8*(num_bytes-1-c));
                                
                                read_message_content(connection, read_buffer, length, callbacks, fin_rsv_opcode);
                            }
                            else
                                connection_error(connection, callbacks, ec);
                        });
                    }
                    else if(length==127) {
                        //8 next bytes is the size of content
                        boost::asio::async_read(*connection->socket, *read_buffer, boost::asio::transfer_exactly(8),
                                [this, connection, read_buffer, &callbacks, fin_rsv_opcode]
                                (const boost::system::error_code& ec, size_t bytes_transferred) {
                            if(!ec) {
                                std::istream stream(read_buffer.get());
                                
                                std::vector<unsigned char> length_bytes;
                                length_bytes.resize(8);
                                stream.read((char*)&length_bytes[0], 8);
                                
                                size_t length=0;
                                int num_bytes=8;
                                for(int c=0;c<num_bytes;c++)
                                    length+=length_bytes[c]<<(8*(num_bytes-1-c));

                                read_message_content(connection, read_buffer, length, callbacks, fin_rsv_opcode);
                            }
                            else
                                connection_error(connection, callbacks, ec);
                        });
                    }
                    else
                        read_message_content(connection, read_buffer, length, callbacks, fin_rsv_opcode);
                }
                else
                    connection_error(connection, callbacks, ec);
            });
        }
        
        void read_message_content(std::shared_ptr<Connection> connection, 
                std::shared_ptr<boost::asio::streambuf> read_buffer, 
                size_t length, Callbacks& callbacks, unsigned char fin_rsv_opcode) {
            boost::asio::async_read(*connection->socket, *read_buffer, boost::asio::transfer_exactly(4+length),
                    [this, connection, read_buffer, length, &callbacks, fin_rsv_opcode]
                    (const boost::system::error_code& ec, size_t bytes_transferred) {
                if(!ec) {
                    std::istream raw_message_data(read_buffer.get());

                    //Read mask
                    std::vector<unsigned char> mask;
                    mask.resize(4);
                    raw_message_data.read((char*)&mask[0], 4);
                    
                    std::shared_ptr<Message> message(new Message());
                    message->length=length;
                    message->fin_rsv_opcode=fin_rsv_opcode;
                    
                    std::ostream message_data_out_stream(&message->data_buffer);
                    for(size_t c=0;c<length;c++) {
                        message_data_out_stream.put(raw_message_data.get()^mask[c%4]);
                    }
                    
                    //If connection close
                    if((fin_rsv_opcode&0x0f)==8) {
                        int status=0;
                        if(length>=2) {
                            unsigned char byte1=message->data.get();
                            unsigned char byte2=message->data.get();
                            status=(byte1<<8)+byte2;
                        }
                        
                        std::stringstream reason_ss;
                        reason_ss << message->data.rdbuf();
                        std::string reason=reason_ss.str();
                        
                        send_close(connection, status, reason);
                        connection_close(connection, callbacks, status, reason);
                        return;
                    }
                    //If ping
                    else if((fin_rsv_opcode&0x0f)==9) {
                        //send pong
                        std::stringstream empty_ss;
                        send(connection, empty_ss, nullptr, fin_rsv_opcode+1);
                    }
                    else if(callbacks.onmessage) {
                        timer_idle_reset(connection);
                        callbacks.onmessage(connection, message);
                    }

                    //Next message
                    read_message(connection, read_buffer, callbacks);
                }
                else
                    connection_error(connection, callbacks, ec);
            });
        }
        
        void connection_open(std::shared_ptr<Connection> connection, const Callbacks& callbacks) {
            timer_idle_init(connection);
            connections_mutex.lock();
            connections.insert(connection);
            connections_mutex.unlock();
            if(callbacks.onopen)
                callbacks.onopen(connection);
        }
        
        void connection_close(std::shared_ptr<Connection> connection, const Callbacks& callbacks, int status, const std::string& reason) {
            timer_idle_cancel(connection);
            connections_mutex.lock();
            connections.erase(connection);
            connections_mutex.unlock();
            if(callbacks.onclose)
                callbacks.onclose(connection, status, reason);
        }
        
        void connection_error(std::shared_ptr<Connection> connection, const Callbacks& callbacks, const boost::system::error_code& ec) {
            timer_idle_cancel(connection);
            connections_mutex.lock();
            connections.erase(connection);
            connections_mutex.unlock();
            if(callbacks.onerror) {
                boost::system::error_code ec_tmp=ec;
                callbacks.onerror(connection, ec_tmp);
            }
        }
        
        void timer_idle_init(std::shared_ptr<Connection> connection) {
            if(timeout_idle>0) {
                connection->timer_idle=std::unique_ptr<boost::asio::deadline_timer>(new boost::asio::deadline_timer(asio_io_service));
                connection->timer_idle->expires_from_now(boost::posix_time::seconds(timeout_idle));
                timer_idle_expired_function(connection);
            }
        }
        void timer_idle_reset(std::shared_ptr<Connection> connection) {
            if(timeout_idle>0 && connection->timer_idle->expires_from_now(boost::posix_time::seconds(timeout_idle))>0) {
                timer_idle_expired_function(connection);
            }
        }
        void timer_idle_cancel(std::shared_ptr<Connection> connection) {
            if(timeout_idle>0)
                connection->timer_idle->cancel();
        }
        
        void timer_idle_expired_function(std::shared_ptr<Connection> connection) {
            connection->timer_idle->async_wait([this, connection](const boost::system::error_code& ec){
                if(!ec) {
                    //1000=normal closure
                    send_close(connection, 1000, "idle timeout");
                }
            });
        }
    };
    
    template<class socket_type>
    class SocketServer : public SocketServerBase<socket_type> {};
    
    typedef boost::asio::ip::tcp::socket WS;
    
    template<>
    class SocketServer<WS> : public SocketServerBase<WS> {
    public:
        SocketServer(unsigned short port, size_t num_threads=1, size_t timeout_request=5, size_t timeout_idle=0, std::string document_root=std::string()) :
                SocketServerBase<WS>::SocketServerBase(port, num_threads, timeout_request, timeout_idle, document_root) {};
        
    private:
        void accept() {
            //Create new socket for this connection (stored in Connection::socket)
            //Shared_ptr is used to pass temporary objects to the asynchronous functions
            std::shared_ptr<Connection> connection(new Connection(new WS(asio_io_service)));
            
            asio_acceptor.async_accept(*connection->socket, [this, connection](const boost::system::error_code& ec) {
                //Immediately start accepting a new connection
                accept();
                if(!ec) {
                    read_handshake(connection);
                }
            });
        }
    };
}
#endif	/* SERVER_WS_HPP */