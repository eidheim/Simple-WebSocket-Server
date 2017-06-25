#ifndef SERVER_WS_HPP
#define	SERVER_WS_HPP

#include "crypto.hpp"
#include "utility.hpp"

#include <thread>
#include <mutex>
#include <unordered_set>
#include <list>
#include <memory>
#include <atomic>
#include <iostream>

#ifdef USE_STANDALONE_ASIO
#include <asio.hpp>
namespace SimpleWeb {
    using error_code = std::error_code;
}
#else
#include <boost/asio.hpp>
namespace SimpleWeb {
    namespace asio = boost::asio;
    using error_code = boost::system::error_code;
}
#endif

// Late 2017 TODO: remove the following checks and always use std::regex
#ifdef USE_BOOST_REGEX
#include <boost/regex.hpp>
namespace SimpleWeb {
    namespace regex = boost;
}
#else
#include <regex>
namespace SimpleWeb {
    namespace regex = std;
}
#endif

namespace SimpleWeb {
    // TODO: remove when onopen, onmessage, etc is removed:
    #ifdef __GNUC__
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    #elif defined(_MSC_VER)
    #pragma warning(push)
    #pragma warning(disable: 4996)
    #endif
    
    template <class socket_type>
    class SocketServer;
        
    template <class socket_type>
    class SocketServerBase {
    public:
        virtual ~SocketServerBase() {}
        
        class SendStream : public std::ostream {
            friend class SocketServerBase<socket_type>;
        private:
            asio::streambuf streambuf;
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
            Connection(const std::shared_ptr<socket_type> &socket): socket(socket), strand(socket->get_io_service()), closed(false) {}
            
            std::string method, path, http_version;

            CaseInsensitiveMultimap header;

            regex::smatch path_match;
            
            std::string remote_endpoint_address;
            unsigned short remote_endpoint_port;
            
        private:
            Connection(socket_type *socket): socket(socket), strand(socket->get_io_service()), closed(false) {}
            
            class SendData {
            public:
                SendData(const std::shared_ptr<SendStream> &header_stream, const std::shared_ptr<SendStream> &message_stream,
                        const std::function<void(const error_code)> &callback) :
                        header_stream(header_stream), message_stream(message_stream), callback(callback) {}
                std::shared_ptr<SendStream> header_stream;
                std::shared_ptr<SendStream> message_stream;
                std::function<void(const error_code)> callback;
            };
            
            std::shared_ptr<socket_type> socket;
            
            asio::strand strand;
            
            std::list<SendData> send_queue;
            
            void send_from_queue(const std::shared_ptr<Connection> &connection) {
                strand.post([this, connection]() {
                    asio::async_write(*socket, send_queue.begin()->header_stream->streambuf,
                            strand.wrap([this, connection](const error_code& ec, size_t /*bytes_transferred*/) {
                        if(!ec) {
                            asio::async_write(*socket, send_queue.begin()->message_stream->streambuf,
                                    strand.wrap([this, connection]
                                    (const error_code& ec, size_t /*bytes_transferred*/) {
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

            std::unique_ptr<asio::deadline_timer> timer_idle;
            
            void read_remote_endpoint_data() {
                try {
                    remote_endpoint_address=socket->lowest_layer().remote_endpoint().address().to_string();
                    remote_endpoint_port=socket->lowest_layer().remote_endpoint().port();
                }
                catch(...) {}
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
            asio::streambuf streambuf;
        };
        
        class Endpoint {
            friend class SocketServerBase<socket_type>;
        private:
            std::unordered_set<std::shared_ptr<Connection> > connections;
            std::mutex connections_mutex;

        public:
            DEPRECATED std::function<void(std::shared_ptr<Connection>)> onopen;
            std::function<void(std::shared_ptr<Connection>)> on_open;
            DEPRECATED std::function<void(std::shared_ptr<Connection>, std::shared_ptr<Message>)> onmessage;
            std::function<void(std::shared_ptr<Connection>, std::shared_ptr<Message>)> on_message;
            DEPRECATED std::function<void(std::shared_ptr<Connection>, int, const std::string&)> onclose;
            std::function<void(std::shared_ptr<Connection>, int, const std::string&)> on_close;
            DEPRECATED std::function<void(std::shared_ptr<Connection>, const error_code&)> onerror;
            std::function<void(std::shared_ptr<Connection>, const error_code&)> on_error;
            
            std::unordered_set<std::shared_ptr<Connection> > get_connections() {
                std::lock_guard<std::mutex> lock(connections_mutex);
                auto copy=connections;
                return copy;
            }
        };
        
        class Config {
            friend class SocketServerBase<socket_type>;
        private:
            Config(unsigned short port): port(port) {}
        public:
            /// Port number to use. Defaults to 80 for HTTP and 443 for HTTPS.
            unsigned short port;
            /// Number of threads that the server will use when start() is called. Defaults to 1 thread.
            size_t thread_pool_size=1;
            /// Timeout on request handling. Defaults to 5 seconds.
            size_t timeout_request=5;
            /// Idle timeout. Defaults to no timeout.
            size_t timeout_idle=0;
            /// IPv4 address in dotted decimal form or IPv6 address in hexadecimal notation.
            /// If empty, the address will be any address.
            std::string address;
            /// Set to false to avoid binding the socket to an address that is already in use. Defaults to true.
            bool reuse_address=true;
        };
        ///Set before calling start().
        Config config;
        
    private:
        class regex_orderable : public regex::regex {
            std::string str;
        public:
            regex_orderable(const char *regex_cstr) : regex::regex(regex_cstr), str(regex_cstr) {}
            regex_orderable(const std::string &regex_str) : regex::regex(regex_str), str(regex_str) {}
            bool operator<(const regex_orderable &rhs) const {
                return str<rhs.str;
            }
        };
    public:
        /// Warning: do not add or remove endpoints after start() is called
        std::map<regex_orderable, Endpoint> endpoint;
        
        virtual void start() {
            for(auto &endp: endpoint) {
                // TODO: remove when onopen, onmessage, etc is removed:
                if(endp.second.onopen)
                    endp.second.on_open=endp.second.onopen;
                if(endp.second.onmessage)
                    endp.second.on_message=endp.second.onmessage;
                if(endp.second.onclose)
                    endp.second.on_close=endp.second.onclose;
                if(endp.second.onerror)
                    endp.second.on_error=endp.second.onerror;
            }
            
            if(!io_service)
                io_service=std::make_shared<asio::io_service>();
            
            if(io_service->stopped())
                io_service->reset();
            
            asio::ip::tcp::endpoint endpoint;
            if(config.address.size()>0)
                endpoint=asio::ip::tcp::endpoint(asio::ip::address::from_string(config.address), config.port);
            else
                endpoint=asio::ip::tcp::endpoint(asio::ip::tcp::v4(), config.port);
            
            if(!acceptor)
                acceptor=std::unique_ptr<asio::ip::tcp::acceptor>(new asio::ip::tcp::acceptor(*io_service));
            acceptor->open(endpoint.protocol());
            acceptor->set_option(asio::socket_base::reuse_address(config.reuse_address));
            acceptor->bind(endpoint);
            acceptor->listen();
            
            accept();
            
            //If thread_pool_size>1, start m_io_service.run() in (thread_pool_size-1) threads for thread-pooling
            threads.clear();
            for(size_t c=1;c<config.thread_pool_size;c++) {
                threads.emplace_back([this](){
                    io_service->run();
                });
            }
            //Main thread
            if(config.thread_pool_size>0)
                io_service->run();

            //Wait for the rest of the threads, if any, to finish as well
            for(auto& t: threads) {
                t.join();
            }
        }
        
        void stop() {
            acceptor->close();
            if(config.thread_pool_size>0)
                io_service->stop();
            
            for(auto &pair: endpoint) {
                std::lock_guard<std::mutex> lock(pair.second.connections_mutex);
                for(auto &connection: pair.second.connections) {
                    connection->socket->lowest_layer().shutdown(asio::ip::tcp::socket::shutdown_both);
                    connection->socket->lowest_layer().close();
                }
                pair.second.connections.clear();
            }
        }
        
        ///fin_rsv_opcode: 129=one fragment, text, 130=one fragment, binary, 136=close connection.
        ///See http://tools.ietf.org/html/rfc6455#section-5.2 for more information
        void send(const std::shared_ptr<Connection> &connection, const std::shared_ptr<SendStream> &message_stream, 
                const std::function<void(const error_code&)>& callback=nullptr, 
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
                const std::function<void(const error_code&)>& callback=nullptr) const {
            //Send close only once (in case close is initiated by server)
            if(connection->closed)
                return;
            connection->closed=true;
            
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
                std::lock_guard<std::mutex> lock(e.second.connections_mutex);
                all_connections.insert(e.second.connections.begin(), e.second.connections.end());
            }
            return all_connections;
        }
        
        /**
         * Upgrades a request, from for instance Simple-Web-Server, to a WebSocket connection.
         * The parameters are moved to the Connection object.
         * See also Server::on_upgrade in the Simple-Web-Server project.
         * The socket's io_service is used, thus running start() is not needed.
         *
         * Example use:
         * server.on_upgrade=[&socket_server] (auto socket, auto request) {
         *   auto connection=std::make_shared<SimpleWeb::SocketServer<SimpleWeb::WS>::Connection>(socket);
         *   connection->method=std::move(request->method);
         *   connection->path=std::move(request->path);
         *   connection->http_version=std::move(request->http_version);
         *   connection->header=std::move(request->header);
         *   connection->remote_endpoint_address=std::move(request->remote_endpoint_address);
         *   connection->remote_endpoint_port=request->remote_endpoint_port;
         *   socket_server.upgrade(connection);
         * }
         */
        void upgrade(const std::shared_ptr<Connection> &connection) {
            auto read_buffer=std::make_shared<asio::streambuf>();
            write_handshake(connection, read_buffer);
        }
        
        /// If you have your own asio::io_service, store its pointer here before running start().
        /// You might also want to set config.thread_pool_size to 0.
        std::shared_ptr<asio::io_service> io_service;
    protected:
        const std::string ws_magic_string="258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        
        std::unique_ptr<asio::ip::tcp::acceptor> acceptor;
        
        std::vector<std::thread> threads;
        
        SocketServerBase(unsigned short port) : config(port) {}
        
        virtual void accept()=0;
        
        std::shared_ptr<asio::deadline_timer> get_timeout_timer(const std::shared_ptr<Connection> &connection, size_t seconds) {
            if(seconds==0)
                return nullptr;
            
            auto timer=std::make_shared<asio::deadline_timer>(connection->socket->get_io_service());
            timer->expires_from_now(boost::posix_time::seconds(static_cast<long>(seconds)));
            timer->async_wait([connection](const error_code& ec){
                if(!ec) {
                    connection->socket->lowest_layer().shutdown(asio::ip::tcp::socket::shutdown_both);
                    connection->socket->lowest_layer().close();
                }
            });
            return timer;
        }

        void read_handshake(const std::shared_ptr<Connection> &connection) {
            connection->read_remote_endpoint_data();
            
            //Create new read_buffer for async_read_until()
            //Shared_ptr is used to pass temporary objects to the asynchronous functions
            auto read_buffer=std::make_shared<asio::streambuf>();

            //Set timeout on the following asio::async-read or write function
            auto timer=get_timeout_timer(connection, config.timeout_request);
            
            asio::async_read_until(*connection->socket, *read_buffer, "\r\n\r\n",
                    [this, connection, read_buffer, timer]
                    (const error_code& ec, size_t /*bytes_transferred*/) {
                if(timer)
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
                                connection->header.emplace(line.substr(0, param_end), line.substr(value_start, line.size()-value_start-1));
                        }
            
                        getline(stream, line);
                    }
                }
            }
        }
        
        void write_handshake(const std::shared_ptr<Connection> &connection, const std::shared_ptr<asio::streambuf> &read_buffer) {
            //Find path- and method-match, and generate response
            for(auto &regex_endpoint: endpoint) {
                regex::smatch path_match;
                if(regex::regex_match(connection->path, path_match, regex_endpoint.first)) {
                    auto write_buffer=std::make_shared<asio::streambuf>();
                    std::ostream handshake(write_buffer.get());

                    if(generate_handshake(connection, handshake)) {
                        connection->path_match=std::move(path_match);
                        //Capture write_buffer in lambda so it is not destroyed before async_write is finished
                        asio::async_write(*connection->socket, *write_buffer, 
                                [this, connection, write_buffer, read_buffer, &regex_endpoint]
                                (const error_code& ec, size_t /*bytes_transferred*/) {
                            if(!ec) {
                                connection_open(connection, regex_endpoint.second);
                                read_message(connection, read_buffer, regex_endpoint.second);
                            }
                            else
                                connection_error(connection, regex_endpoint.second, ec);
                        });
                    }
                    return;
                }
            }
        }
        
        bool generate_handshake(const std::shared_ptr<Connection> &connection, std::ostream& handshake) const {
            auto header_it=connection->header.find("Sec-WebSocket-Key");
            if(header_it==connection->header.end())
                return false;
            
            auto sha1=Crypto::sha1(header_it->second+ws_magic_string);

            handshake << "HTTP/1.1 101 Web Socket Protocol Handshake\r\n";
            handshake << "Upgrade: websocket\r\n";
            handshake << "Connection: Upgrade\r\n";
            handshake << "Sec-WebSocket-Accept: " << Crypto::Base64::encode(sha1) << "\r\n";
            handshake << "\r\n";
            
            return true;
        }
        
        void read_message(const std::shared_ptr<Connection> &connection,
                          const std::shared_ptr<asio::streambuf> &read_buffer, Endpoint& endpoint) const {
            asio::async_read(*connection->socket, *read_buffer, asio::transfer_exactly(2),
                    [this, connection, read_buffer, &endpoint]
                    (const error_code& ec, size_t bytes_transferred) {
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
                        send_close(connection, 1002, reason, [this, connection](const error_code& /*ec*/) {});
                        connection_close(connection, endpoint, 1002, reason);
                        return;
                    }
                    
                    size_t length=(first_bytes[1]&127);

                    if(length==126) {
                        //2 next bytes is the size of content
                        asio::async_read(*connection->socket, *read_buffer, asio::transfer_exactly(2),
                                [this, connection, read_buffer, &endpoint, fin_rsv_opcode]
                                (const error_code& ec, size_t /*bytes_transferred*/) {
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
                        asio::async_read(*connection->socket, *read_buffer, asio::transfer_exactly(8),
                                [this, connection, read_buffer, &endpoint, fin_rsv_opcode]
                                (const error_code& ec, size_t /*bytes_transferred*/) {
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
        
        void read_message_content(const std::shared_ptr<Connection> &connection, const std::shared_ptr<asio::streambuf> &read_buffer,
                                  size_t length, Endpoint& endpoint, unsigned char fin_rsv_opcode) const {
            asio::async_read(*connection->socket, *read_buffer, asio::transfer_exactly(4+length),
                    [this, connection, read_buffer, length, &endpoint, fin_rsv_opcode]
                    (const error_code& ec, size_t /*bytes_transferred*/) {
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
                        send_close(connection, status, reason, [this, connection](const error_code& /*ec*/) {});
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
                        else if(endpoint.on_message) {
                            timer_idle_reset(connection);
                            endpoint.on_message(connection, message);
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
            
            {
                std::lock_guard<std::mutex> lock(endpoint.connections_mutex);
                endpoint.connections.insert(connection);
            }
            
            if(endpoint.on_open)
                endpoint.on_open(connection);
        }
        
        void connection_close(const std::shared_ptr<Connection> &connection, Endpoint& endpoint, int status, const std::string& reason) const {
            timer_idle_cancel(connection);
            
            {
                std::lock_guard<std::mutex> lock(endpoint.connections_mutex);
                endpoint.connections.erase(connection);
            }
            
            if(endpoint.on_close)
                endpoint.on_close(connection, status, reason);
        }
        
        void connection_error(const std::shared_ptr<Connection> &connection, Endpoint& endpoint, const error_code& ec) const {
            timer_idle_cancel(connection);
            
            {
                std::lock_guard<std::mutex> lock(endpoint.connections_mutex);
                endpoint.connections.erase(connection);
            }
            
            if(endpoint.on_error)
                endpoint.on_error(connection, ec);
        }
        
        void timer_idle_init(const std::shared_ptr<Connection> &connection) {
            if(config.timeout_idle>0) {
                connection->timer_idle=std::unique_ptr<asio::deadline_timer>(new asio::deadline_timer(connection->socket->get_io_service()));
                connection->timer_idle->expires_from_now(boost::posix_time::seconds(static_cast<unsigned long>(config.timeout_idle)));
                timer_idle_expired_function(connection);
            }
        }
        void timer_idle_reset(const std::shared_ptr<Connection> &connection) const {
            if(config.timeout_idle>0 && connection->timer_idle->expires_from_now(boost::posix_time::seconds(static_cast<unsigned long>(config.timeout_idle)))>0)
                timer_idle_expired_function(connection);
        }
        void timer_idle_cancel(const std::shared_ptr<Connection> &connection) const {
            if(config.timeout_idle>0)
                connection->timer_idle->cancel();
        }
        
        void timer_idle_expired_function(const std::shared_ptr<Connection> &connection) const {
            connection->timer_idle->async_wait([this, connection](const error_code& ec){
                if(!ec)
                    send_close(connection, 1000, "idle timeout"); //1000=normal closure
            });
        }
    };
    
    template<class socket_type>
    class SocketServer : public SocketServerBase<socket_type> {};
    
    typedef asio::ip::tcp::socket WS;
    
    template<>
    class SocketServer<WS> : public SocketServerBase<WS> {
    public:
        DEPRECATED SocketServer(unsigned short port, size_t thread_pool_size=1, size_t timeout_request=5, size_t timeout_idle=0) : 
                SocketServer() {
            config.port=port;
            config.thread_pool_size=thread_pool_size;
            config.timeout_request=timeout_request;
            config.timeout_idle=timeout_idle;
        };
        
        SocketServer() : SocketServerBase<WS>(80) {}
        
    protected:
        void accept() {
            //Create new socket for this connection (stored in Connection::socket)
            //Shared_ptr is used to pass temporary objects to the asynchronous functions
            std::shared_ptr<Connection> connection(new Connection(new WS(*io_service)));
            
            acceptor->async_accept(*connection->socket, [this, connection](const error_code& ec) {
                //Immediately start accepting a new connection (if io_service hasn't been stopped)
                if (ec != asio::error::operation_aborted)
                    accept();

                if(!ec) {
                    asio::ip::tcp::no_delay option(true);
                    connection->socket->set_option(option);
                    
                    read_handshake(connection);
                }
            });
        }
    };
    // TODO: remove when onopen, onmessage, etc is removed:
    #ifdef __GNUC__
    #pragma GCC diagnostic pop
    #elif defined(_MSC_VER)
    #pragma warning(pop)
    #endif
}

#endif	/* SERVER_WS_HPP */
