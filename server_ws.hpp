#ifndef SERVER_WS_HPP
#define	SERVER_WS_HPP

#include "crypto.hpp"

#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>

#include <unordered_map>
#include <thread>
#include <mutex>
#include <unordered_set>
#include <list>
#include <memory>
#include <atomic>
#include <iostream>

// Late 2017 TODO: remove the following checks and always use std::regex
#ifdef USE_BOOST_REGEX
#include <boost/regex.hpp>
#define REGEX_NS boost
#else
#include <regex>
#define REGEX_NS std
#endif

namespace SimpleWeb {
    template <class socket_type>
    class SocketServer;
        
    template <class socket_type>
    class SocketServerBase {
    public:
        virtual ~SocketServerBase() {}
        
        class SendStream : public std::ostream {
            friend class SocketServerBase<socket_type>;
        private:
            boost::asio::streambuf streambuf;
        public:
            SendStream(): std::ostream(&streambuf) {}
            size_t size() {
                return streambuf.size();
            }
        };
        
        class Connection {
            friend class SocketServerBase<socket_type>;
            friend class SocketServer<socket_type>;
            
        public:
            std::string method, path, http_version;

            std::unordered_map<std::string, std::string> header;

            REGEX_NS::smatch path_match;
            
            std::string remote_endpoint_address;
            unsigned short remote_endpoint_port;
            
        private:
            Connection(socket_type *socket): socket(socket), strand(socket->get_io_service()), closed(false) {}
            
            class SendData {
            public:
                SendData(const std::shared_ptr<SendStream> &header_stream, const std::shared_ptr<SendStream> &message_stream,
                        const std::function<void(const boost::system::error_code)> &callback) :
                        header_stream(header_stream), message_stream(message_stream), callback(callback) {}
                std::shared_ptr<SendStream> header_stream;
                std::shared_ptr<SendStream> message_stream;
                std::function<void(const boost::system::error_code)> callback;
            };
            
            //boost::asio::ssl::stream constructor needs move, until then we store socket as unique_ptr
            std::unique_ptr<socket_type> socket;
            
            boost::asio::strand strand;
            
            std::list<SendData> send_queue;
            
            void send_from_queue(const std::shared_ptr<Connection> &connection) {
                strand.post([this, connection]() {
                    boost::asio::async_write(*socket, send_queue.begin()->header_stream->streambuf,
                            strand.wrap([this, connection](const boost::system::error_code& ec, size_t /*bytes_transferred*/) {
                        if(!ec) {
                            boost::asio::async_write(*socket, send_queue.begin()->message_stream->streambuf,
                                    strand.wrap([this, connection]
                                    (const boost::system::error_code& ec, size_t /*bytes_transferred*/) {
                                auto send_queued=send_queue.begin();
                                if(send_queued->callback)
                                    send_queued->callback(ec);
                                if(!ec) {
                                    send_queue.erase(send_queued);
                                    if(send_queue.size()>0)
                                        send_from_queue(connection);
                                }
                                else
                                    send_queue.clear();
                            }));
                        }
                        else {
                            auto send_queued=send_queue.begin();
                            if(send_queued->callback)
                                send_queued->callback(ec);
                            send_queue.clear();
                        }
                    }));
                });
            }
            
            std::atomic<bool> closed;

            std::unique_ptr<boost::asio::deadline_timer> timer_idle;
            
            void read_remote_endpoint_data() {
                try {
                    remote_endpoint_address=socket->lowest_layer().remote_endpoint().address().to_string();
                    remote_endpoint_port=socket->lowest_layer().remote_endpoint().port();
                }
                catch(const std::exception& e) {
                    std::cerr << e.what() << std::endl;
                }
            }
        };
        
        class Message : public std::istream {
            friend class SocketServerBase<socket_type>;
            
        public:
            unsigned char fin_rsv_opcode;
            size_t size() {
                return length;
            }
            std::string string() {
                std::stringstream ss;
                ss << rdbuf();
                return ss.str();
            }
        private:
            Message(): std::istream(&streambuf) {}
            size_t length;
            boost::asio::streambuf streambuf;
        };
        
        class Endpoint {
            friend class SocketServerBase<socket_type>;
        private:
            std::unordered_set<std::shared_ptr<Connection> > connections;
            std::mutex connections_mutex;

        public:            
            std::function<void(std::shared_ptr<Connection>)> onopen;
            std::function<void(std::shared_ptr<Connection>, std::shared_ptr<Message>)> onmessage;
            std::function<void(std::shared_ptr<Connection>, const boost::system::error_code&)> onerror;
            std::function<void(std::shared_ptr<Connection>, int, const std::string&)> onclose;
            
            std::unordered_set<std::shared_ptr<Connection> > get_connections() {
                connections_mutex.lock();
                auto copy=connections;
                connections_mutex.unlock();
                return copy;
            }
        };
        
        class Config {
            friend class SocketServerBase<socket_type>;
        private:
            Config(unsigned short port, size_t num_threads): num_threads(num_threads), port(port), reuse_address(true) {}
            size_t num_threads;
        public:
            unsigned short port;
            ///IPv4 address in dotted decimal form or IPv6 address in hexadecimal notation.
            ///If empty, the address will be any address.
            std::string address;
            ///Set to false to avoid binding the socket to an address that is already in use.
            bool reuse_address;
        };
        ///Set before calling start().
        Config config;
        
        std::map<std::string, Endpoint> endpoint;
        
    private:
        std::vector<std::pair<REGEX_NS::regex, Endpoint*> > opt_endpoint;
        
    public:
        void start() {
            opt_endpoint.clear();
            for(auto& endp: endpoint) {
                opt_endpoint.emplace_back(REGEX_NS::regex(endp.first), &endp.second);
            }
            
            if(!io_service)
                io_service=std::make_shared<boost::asio::io_service>();
            
            if(io_service->stopped())
                io_service->reset();
            
            boost::asio::ip::tcp::endpoint endpoint;
            if(config.address.size()>0)
                endpoint=boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string(config.address), config.port);
            else
                endpoint=boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), config.port);
            
            if(!acceptor)
                acceptor=std::unique_ptr<boost::asio::ip::tcp::acceptor>(new boost::asio::ip::tcp::acceptor(*io_service));
            acceptor->open(endpoint.protocol());
            acceptor->set_option(boost::asio::socket_base::reuse_address(config.reuse_address));
            acceptor->bind(endpoint);
            acceptor->listen();
            
            accept();
            
            //If num_threads>1, start m_io_service.run() in (num_threads-1) threads for thread-pooling
            threads.clear();
            for(size_t c=1;c<config.num_threads;c++) {
                threads.emplace_back([this](){
                    io_service->run();
                });
            }
            //Main thread
            if(config.num_threads>0)
                io_service->run();

            //Wait for the rest of the threads, if any, to finish as well
            for(auto& t: threads) {
                t.join();
            }
        }
        
        void stop() {
            acceptor->close();
            if(config.num_threads>0)
                io_service->stop();
            
            for(auto& p: endpoint)
                p.second.connections.clear();
        }
        
        ///fin_rsv_opcode: 129=one fragment, text, 130=one fragment, binary, 136=close connection.
        ///See http://tools.ietf.org/html/rfc6455#section-5.2 for more information
        void send(const std::shared_ptr<Connection> &connection, const std::shared_ptr<SendStream> &message_stream, 
                const std::function<void(const boost::system::error_code&)>& callback=nullptr, 
                unsigned char fin_rsv_opcode=129) const {
            if(fin_rsv_opcode!=136)
                timer_idle_reset(connection);
            
            auto header_stream=std::make_shared<SendStream>();

            size_t length=message_stream->size();

            header_stream->put(fin_rsv_opcode);
            //unmasked (first length byte<128)
            if(length>=126) {
                int num_bytes;
                if(length>0xffff) {
                    num_bytes=8;
                    header_stream->put(127);
                }
                else {
                    num_bytes=2;
                    header_stream->put(126);
                }
                
                for(int c=num_bytes-1;c>=0;c--) {
                    header_stream->put((static_cast<unsigned long long>(length) >> (8 * c)) % 256);
                }
            }
            else
                header_stream->put(static_cast<unsigned char>(length));

            connection->strand.post([this, connection, header_stream, message_stream, callback]() {
                connection->send_queue.emplace_back(header_stream, message_stream, callback);
                if(connection->send_queue.size()==1)
                    connection->send_from_queue(connection);
            });
        }

        void send_close(const std::shared_ptr<Connection> &connection, int status, const std::string& reason="",
                const std::function<void(const boost::system::error_code&)>& callback=nullptr) const {
            //Send close only once (in case close is initiated by server)
            if(connection->closed.load()) {
                return;
            }
            connection->closed.store(true);
            
            auto send_stream=std::make_shared<SendStream>();
            
            send_stream->put(status>>8);
            send_stream->put(status%256);
            
            *send_stream << reason;

            //fin_rsv_opcode=136: message close
            send(connection, send_stream, callback, 136);
        }
        
        std::unordered_set<std::shared_ptr<Connection> > get_connections() {
            std::unordered_set<std::shared_ptr<Connection> > all_connections;
            for(auto& e: endpoint) {
                e.second.connections_mutex.lock();
                all_connections.insert(e.second.connections.begin(), e.second.connections.end());
                e.second.connections_mutex.unlock();
            }
            return all_connections;
        }
        
        /// If you have your own boost::asio::io_service, store its pointer here before running start().
        /// You might also want to set config.num_threads to 0.
        std::shared_ptr<boost::asio::io_service> io_service;
    protected:
        const std::string ws_magic_string="258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        
        std::unique_ptr<boost::asio::ip::tcp::acceptor> acceptor;
        
        std::vector<std::thread> threads;
        
        size_t timeout_request;
        size_t timeout_idle;
        
        SocketServerBase(unsigned short port, size_t num_threads, size_t timeout_request, size_t timeout_idle) : 
                config(port, num_threads), timeout_request(timeout_request), timeout_idle(timeout_idle) {}
        
        virtual void accept()=0;
        
        std::shared_ptr<boost::asio::deadline_timer> set_timeout_on_connection(const std::shared_ptr<Connection> &connection, size_t seconds) {
            std::shared_ptr<boost::asio::deadline_timer> timer(new boost::asio::deadline_timer(*io_service));
            timer->expires_from_now(boost::posix_time::seconds(static_cast<long>(seconds)));
            timer->async_wait([connection](const boost::system::error_code& ec){
                if(!ec) {
                    connection->socket->lowest_layer().shutdown(boost::asio::ip::tcp::socket::shutdown_both);
                    connection->socket->lowest_layer().close();
                }
            });
            return timer;
        }

        void read_handshake(const std::shared_ptr<Connection> &connection) {
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
                    (const boost::system::error_code& ec, size_t /*bytes_transferred*/) {
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
        
        void parse_handshake(const std::shared_ptr<Connection> &connection, std::istream& stream) const {
            std::string line;
            getline(stream, line);
            size_t method_end;
            if((method_end=line.find(' '))!=std::string::npos) {
                size_t path_end;
                if((path_end=line.find(' ', method_end+1))!=std::string::npos) {
                    connection->method=line.substr(0, method_end);
                    connection->path=line.substr(method_end+1, path_end-method_end-1);
                    if((path_end+6)<line.size())
                        connection->http_version=line.substr(path_end+6, line.size()-(path_end+6)-1);
                    else
                        connection->http_version="1.1";
            
                    getline(stream, line);
                    size_t param_end;
                    while((param_end=line.find(':'))!=std::string::npos) {
                        size_t value_start=param_end+1;
                        if((value_start)<line.size()) {
                            if(line[value_start]==' ')
                                value_start++;
                            if(value_start<line.size())
                                connection->header.insert(std::make_pair(line.substr(0, param_end), line.substr(value_start, line.size()-value_start-1)));
                        }
            
                        getline(stream, line);
                    }
                }
            }
        }
        
        void write_handshake(const std::shared_ptr<Connection> &connection, const std::shared_ptr<boost::asio::streambuf> &read_buffer) {
            //Find path- and method-match, and generate response
            for(auto& endp: opt_endpoint) {
                REGEX_NS::smatch path_match;
                if(REGEX_NS::regex_match(connection->path, path_match, endp.first)) {
                    std::shared_ptr<boost::asio::streambuf> write_buffer(new boost::asio::streambuf);
                    std::ostream handshake(write_buffer.get());

                    if(generate_handshake(connection, handshake)) {
                        connection->path_match=std::move(path_match);
                        //Capture write_buffer in lambda so it is not destroyed before async_write is finished
                        boost::asio::async_write(*connection->socket, *write_buffer, 
                                [this, connection, write_buffer, read_buffer, &endp]
                                (const boost::system::error_code& ec, size_t /*bytes_transferred*/) {
                            if(!ec) {
                                connection_open(connection, *endp.second);
                                read_message(connection, read_buffer, *endp.second);
                            }
                            else
                                connection_error(connection, *endp.second, ec);
                        });
                    }
                    return;
                }
            }
        }
        
        bool generate_handshake(const std::shared_ptr<Connection> &connection, std::ostream& handshake) const {
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
        
        void read_message(const std::shared_ptr<Connection> &connection,
                          const std::shared_ptr<boost::asio::streambuf> &read_buffer, Endpoint& endpoint) const {
            boost::asio::async_read(*connection->socket, *read_buffer, boost::asio::transfer_exactly(2),
                    [this, connection, read_buffer, &endpoint]
                    (const boost::system::error_code& ec, size_t bytes_transferred) {
                if(!ec) {
                    if(bytes_transferred==0) { //TODO: why does this happen sometimes?
                        read_message(connection, read_buffer, endpoint);
                        return;
                    }
                    std::istream stream(read_buffer.get());

                    std::vector<unsigned char> first_bytes;
                    first_bytes.resize(2);
                    stream.read((char*)&first_bytes[0], 2);
                    
                    unsigned char fin_rsv_opcode=first_bytes[0];
                    
                    //Close connection if unmasked message from client (protocol error)
                    if(first_bytes[1]<128) {
                        const std::string reason("message from client not masked");
                        send_close(connection, 1002, reason, [this, connection](const boost::system::error_code& /*ec*/) {});
                        connection_close(connection, endpoint, 1002, reason);
                        return;
                    }
                    
                    size_t length=(first_bytes[1]&127);

                    if(length==126) {
                        //2 next bytes is the size of content
                        boost::asio::async_read(*connection->socket, *read_buffer, boost::asio::transfer_exactly(2),
                                [this, connection, read_buffer, &endpoint, fin_rsv_opcode]
                                (const boost::system::error_code& ec, size_t /*bytes_transferred*/) {
                            if(!ec) {
                                std::istream stream(read_buffer.get());
                                
                                std::vector<unsigned char> length_bytes;
                                length_bytes.resize(2);
                                stream.read((char*)&length_bytes[0], 2);
                                
                                size_t length=0;
                                int num_bytes=2;
                                for(int c=0;c<num_bytes;c++)
                                    length+=length_bytes[c]<<(8*(num_bytes-1-c));
                                
                                read_message_content(connection, read_buffer, length, endpoint, fin_rsv_opcode);
                            }
                            else
                                connection_error(connection, endpoint, ec);
                        });
                    }
                    else if(length==127) {
                        //8 next bytes is the size of content
                        boost::asio::async_read(*connection->socket, *read_buffer, boost::asio::transfer_exactly(8),
                                [this, connection, read_buffer, &endpoint, fin_rsv_opcode]
                                (const boost::system::error_code& ec, size_t /*bytes_transferred*/) {
                            if(!ec) {
                                std::istream stream(read_buffer.get());
                                
                                std::vector<unsigned char> length_bytes;
                                length_bytes.resize(8);
                                stream.read((char*)&length_bytes[0], 8);
                                
                                size_t length=0;
                                int num_bytes=8;
                                for(int c=0;c<num_bytes;c++)
                                    length+=length_bytes[c]<<(8*(num_bytes-1-c));

                                read_message_content(connection, read_buffer, length, endpoint, fin_rsv_opcode);
                            }
                            else
                                connection_error(connection, endpoint, ec);
                        });
                    }
                    else
                        read_message_content(connection, read_buffer, length, endpoint, fin_rsv_opcode);
                }
                else
                    connection_error(connection, endpoint, ec);
            });
        }
        
        void read_message_content(const std::shared_ptr<Connection> &connection, const std::shared_ptr<boost::asio::streambuf> &read_buffer,
                                  size_t length, Endpoint& endpoint, unsigned char fin_rsv_opcode) const {
            boost::asio::async_read(*connection->socket, *read_buffer, boost::asio::transfer_exactly(4+length),
                    [this, connection, read_buffer, length, &endpoint, fin_rsv_opcode]
                    (const boost::system::error_code& ec, size_t /*bytes_transferred*/) {
                if(!ec) {
                    std::istream raw_message_data(read_buffer.get());

                    //Read mask
                    std::vector<unsigned char> mask;
                    mask.resize(4);
                    raw_message_data.read((char*)&mask[0], 4);
                    
                    std::shared_ptr<Message> message(new Message());
                    message->length=length;
                    message->fin_rsv_opcode=fin_rsv_opcode;
                    
                    std::ostream message_data_out_stream(&message->streambuf);
                    for(size_t c=0;c<length;c++) {
                        message_data_out_stream.put(raw_message_data.get()^mask[c%4]);
                    }
                    
                    //If connection close
                    if((fin_rsv_opcode&0x0f)==8) {
                        int status=0;
                        if(length>=2) {
                            unsigned char byte1=message->get();
                            unsigned char byte2=message->get();
                            status=(byte1<<8)+byte2;
                        }
                        
                        auto reason=message->string();
                        send_close(connection, status, reason, [this, connection](const boost::system::error_code& /*ec*/) {});
                        connection_close(connection, endpoint, status, reason);
                        return;
                    }
                    else {
                        //If ping
                        if((fin_rsv_opcode&0x0f)==9) {
                            //send pong
                            auto empty_send_stream=std::make_shared<SendStream>();
                            send(connection, empty_send_stream, nullptr, fin_rsv_opcode+1);
                        }
                        else if(endpoint.onmessage) {
                            timer_idle_reset(connection);
                            endpoint.onmessage(connection, message);
                        }
    
                        //Next message
                        read_message(connection, read_buffer, endpoint);
                    }
                }
                else
                    connection_error(connection, endpoint, ec);
            });
        }
        
        void connection_open(const std::shared_ptr<Connection> &connection, Endpoint& endpoint) {
            timer_idle_init(connection);
            
            endpoint.connections_mutex.lock();
            endpoint.connections.insert(connection);
            endpoint.connections_mutex.unlock();
            
            if(endpoint.onopen)
                endpoint.onopen(connection);
        }
        
        void connection_close(const std::shared_ptr<Connection> &connection, Endpoint& endpoint, int status, const std::string& reason) const {
            timer_idle_cancel(connection);
            
            endpoint.connections_mutex.lock();
            endpoint.connections.erase(connection);
            endpoint.connections_mutex.unlock();    
            
            if(endpoint.onclose)
                endpoint.onclose(connection, status, reason);
        }
        
        void connection_error(const std::shared_ptr<Connection> &connection, Endpoint& endpoint, const boost::system::error_code& ec) const {
            timer_idle_cancel(connection);
            
            endpoint.connections_mutex.lock();
            endpoint.connections.erase(connection);
            endpoint.connections_mutex.unlock();
            
            if(endpoint.onerror) {
                boost::system::error_code ec_tmp=ec;
                endpoint.onerror(connection, ec_tmp);
            }
        }
        
        void timer_idle_init(const std::shared_ptr<Connection> &connection) {
            if(timeout_idle>0) {
                connection->timer_idle=std::unique_ptr<boost::asio::deadline_timer>(new boost::asio::deadline_timer(*io_service));
                connection->timer_idle->expires_from_now(boost::posix_time::seconds(static_cast<unsigned long>(timeout_idle)));
                timer_idle_expired_function(connection);
            }
        }
        void timer_idle_reset(const std::shared_ptr<Connection> &connection) const {
            if(timeout_idle>0 && connection->timer_idle->expires_from_now(boost::posix_time::seconds(static_cast<unsigned long>(timeout_idle)))>0) {
                timer_idle_expired_function(connection);
            }
        }
        void timer_idle_cancel(const std::shared_ptr<Connection> &connection) const {
            if(timeout_idle>0)
                connection->timer_idle->cancel();
        }
        
        void timer_idle_expired_function(const std::shared_ptr<Connection> &connection) const {
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
        SocketServer(unsigned short port, size_t num_threads=1, size_t timeout_request=5, size_t timeout_idle=0) : 
                SocketServerBase<WS>::SocketServerBase(port, num_threads, timeout_request, timeout_idle) {};
        
    protected:
        void accept() {
            //Create new socket for this connection (stored in Connection::socket)
            //Shared_ptr is used to pass temporary objects to the asynchronous functions
            std::shared_ptr<Connection> connection(new Connection(new WS(*io_service)));
            
            acceptor->async_accept(*connection->socket, [this, connection](const boost::system::error_code& ec) {
                //Immediately start accepting a new connection (if io_service hasn't been stopped)
                if (ec != boost::asio::error::operation_aborted)
                    accept();

                if(!ec) {
                    boost::asio::ip::tcp::no_delay option(true);
                    connection->socket->set_option(option);
                    
                    read_handshake(connection);
                }
            });
        }
    };
}
#endif	/* SERVER_WS_HPP */
