#ifndef CLIENT_WS_HPP
#define	CLIENT_WS_HPP

#include "crypto.hpp"

#include <boost/asio.hpp>

#include <unordered_map>
#include <iostream>
#include <random>

namespace SimpleWeb {
    template <class socket_type>
    class SocketClient;
    
    template <class socket_type>
    class SocketClientBase {
    public:
        class Connection {
            friend class SocketClientBase<socket_type>;
            friend class SocketClient<socket_type>;

        public:
            std::unordered_map<std::string, std::string> header;
            std::string remote_endpoint_address;
            unsigned short remote_endpoint_port;
            
            Connection(socket_type* socket): socket(socket), closed(false) {}
        private:
            std::unique_ptr<socket_type> socket;
            
            std::atomic<bool> closed;
            
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
        
        std::unique_ptr<Connection> connection;
        
        class Message : public std::istream {
            friend class SocketClientBase<socket_type>;
            
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
        
        class SendStream : public std::iostream {
            friend class SocketClientBase<socket_type>;
        private:
            bool sending=false; //Currently not in use, but might be in a future version
            boost::asio::streambuf streambuf;
        public:
            SendStream(): std::iostream(&streambuf) {}
            size_t size() {
                return streambuf.size();
            }
        };
        
        std::function<void(void)> onopen;
        std::function<void(std::shared_ptr<Message>)> onmessage;
        std::function<void(const boost::system::error_code&)> onerror;
        std::function<void(int, const std::string&)> onclose;
        
        void start() {
            connect();
            
            asio_io_service.run();
        }
        
        void stop() {
            asio_io_service.stop();
        }
        
        void send(std::shared_ptr<SendStream> send_stream, const std::function<void(const boost::system::error_code&)>& callback=nullptr, 
                        unsigned char fin_rsv_opcode=129) {
            //Create mask
            std::vector<unsigned char> mask;
            mask.resize(4);
            std::uniform_int_distribution<unsigned char> dist;
            std::random_device rd;
            for(int c=0;c<4;c++) {
                mask[c]=dist(rd);
            }

            std::shared_ptr<boost::asio::streambuf> buffer(new boost::asio::streambuf);
            std::ostream stream(buffer.get());
            
            size_t length=send_stream->size();
            
            stream.put(fin_rsv_opcode);
            //masked (first length byte>=128)
            if(length>=126) {
                int num_bytes;
                if(length>0xffff) {
                    num_bytes=8;
                    stream.put(127+128);
                }
                else {
                    num_bytes=2;
                    stream.put(126+128);
                }
                
                for(int c=num_bytes-1;c>=0;c--) {
                    stream.put((length>>(8*c))%256);
                }
            }
            else
                stream.put(length+128);
            
            for(int c=0;c<4;c++) {
                stream.put(mask[c]);
            }
            
            for(size_t c=0;c<length;c++) {
                stream.put(send_stream->get()^mask[c%4]);
            }
            
            //Need to copy the callback-function in case its destroyed
            boost::asio::async_write(*connection->socket, *buffer, 
                    [this, buffer, callback](const boost::system::error_code& ec, size_t bytes_transferred) {
                if(callback) {
                    callback(ec);
                }
            });
        }
        
        void send_close(int status, const std::string& reason="") {
            //Send close only once (in case close is initiated by client)
            if(connection->closed.load()) {
                return;
            }
            connection->closed.store(true);
            
            auto send_stream=std::make_shared<SendStream>();
            
            send_stream->put(status>>8);
            send_stream->put(status%256);
            
            *send_stream << reason;

            //fin_rsv_opcode=136: message close
            send(send_stream, [](const boost::system::error_code& ec){}, 136);
        }
        
    protected:
        const std::string ws_magic_string="258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        
        boost::asio::io_service asio_io_service;
        boost::asio::ip::tcp::endpoint asio_endpoint;
        boost::asio::ip::tcp::resolver asio_resolver;
        
        std::string host;
        unsigned short port;
        std::string path;
                
        SocketClientBase(const std::string& host_port_path, unsigned short default_port) : 
                asio_resolver(asio_io_service) {
            size_t host_end=host_port_path.find(':');
            size_t host_port_end=host_port_path.find('/');
            if(host_end==std::string::npos) {
                host_end=host_port_end;
                port=default_port;
            }
            else {
                if(host_port_end==std::string::npos)
                    port=(unsigned short)stoul(host_port_path.substr(host_end+1));
                else
                    port=(unsigned short)stoul(host_port_path.substr(host_end+1, host_port_end-(host_end+1)));
            }
            if(host_port_end==std::string::npos) {
                path="/";
            }
            else {
                path=host_port_path.substr(host_port_end);
            }
            if(host_end==std::string::npos)
                host=host_port_path;
            else
                host=host_port_path.substr(0, host_end);
        }
        
        virtual void connect()=0;
        
        void handshake() {
            connection->read_remote_endpoint_data();
            
            std::shared_ptr<boost::asio::streambuf> write_buffer(new boost::asio::streambuf);
            
            std::ostream request(write_buffer.get());
            
            request << "GET " << path << " HTTP/1.1" << "\r\n";
            request << "Host: " << host << "\r\n";
            request << "Upgrade: websocket\r\n";
            request << "Connection: Upgrade\r\n";

            //Make random 16-byte nonce
            std::string nonce;
            nonce.resize(16);
            std::uniform_int_distribution<unsigned char> dist;
            std::random_device rd;
            for(int c=0;c<16;c++)
                nonce[c]=dist(rd);

            std::string nonce_base64=Crypto::Base64::encode(nonce);
            request << "Sec-WebSocket-Key: " << nonce_base64 << "\r\n";
            request << "Sec-WebSocket-Version: 13\r\n";
            request << "\r\n";
            
            //test this to base64::decode(Sec-WebSocket-Accept)
            std::shared_ptr<std::string> accept_sha1(new std::string(Crypto::SHA1(nonce_base64+ws_magic_string)));
            
            boost::asio::async_write(*connection->socket, *write_buffer, 
                    [this, write_buffer, accept_sha1]
                    (const boost::system::error_code& ec, size_t bytes_transferred) {
                if(!ec) {
                    std::shared_ptr<Message> message(new Message());

                    boost::asio::async_read_until(*connection->socket, message->streambuf, "\r\n\r\n",
                            [this, message, accept_sha1]
                            (const boost::system::error_code& ec, size_t bytes_transferred) {
                        if(!ec) {                            
                            parse_handshake(*message);
                            if(Crypto::Base64::decode(connection->header["Sec-WebSocket-Accept"])==*accept_sha1) {
                                if(onopen)
                                    onopen();
                                read_message(message);
                            }
                            else
                                throw std::invalid_argument("WebSocket handshake failed");
                        }
                    });
                }
                else
                    throw std::invalid_argument("Failed sending handshake");
            });
        }
        
        void parse_handshake(std::istream& stream) const {
            std::string line;
            getline(stream, line);
            //Not parsing the first line
            
            getline(stream, line);
            size_t param_end=line.find(':');
            while(param_end!=std::string::npos) {                
                size_t value_start=param_end+1;
                if(line[value_start]==' ')
                    value_start++;

                connection->header[line.substr(0, param_end)]=line.substr(value_start, line.size()-value_start-1);

                getline(stream, line);
                param_end=line.find(':');
            }
        }
        
        void read_message(std::shared_ptr<Message> message) {
            boost::asio::async_read(*connection->socket, message->streambuf, boost::asio::transfer_exactly(2),
                    [this, message](const boost::system::error_code& ec, size_t bytes_transferred) {
                if(!ec) {
                    std::vector<unsigned char> first_bytes;
                    first_bytes.resize(2);
                    message->read((char*)&first_bytes[0], 2);
                    
                    message->fin_rsv_opcode=first_bytes[0];
                    
                    //Close connection if masked message from server (protocol error)
                    if(first_bytes[1]>=128) {
                        const std::string reason="message from server masked";
                        send_close(1002, reason);
                        if(onclose)
                            onclose(1002, reason);
                        return;
                    }
                    
                    size_t length=(first_bytes[1]&127);
                    
                    if(length==126) {
                        //2 next bytes is the size of content
                        boost::asio::async_read(*connection->socket, message->streambuf, boost::asio::transfer_exactly(2),
                                [this, message]
                                (const boost::system::error_code& ec, size_t bytes_transferred) {
                            if(!ec) {
                                std::vector<unsigned char> length_bytes;
                                length_bytes.resize(2);
                                message->read((char*)&length_bytes[0], 2);
                                
                                size_t length=0;
                                int num_bytes=2;
                                for(int c=0;c<num_bytes;c++)
                                    length+=length_bytes[c]<<(8*(num_bytes-1-c));
                                
                                message->length=length;
                                read_message_content(message);
                            }
                            else {
                                if(onerror)
                                    onerror(ec);
                            }
                        });
                    }
                    else if(length==127) {
                        //8 next bytes is the size of content
                        boost::asio::async_read(*connection->socket, message->streambuf, boost::asio::transfer_exactly(8),
                                [this, message]
                                (const boost::system::error_code& ec, size_t bytes_transferred) {
                            if(!ec) {
                                std::vector<unsigned char> length_bytes;
                                length_bytes.resize(8);
                                message->read((char*)&length_bytes[0], 8);
                                
                                size_t length=0;
                                int num_bytes=8;
                                for(int c=0;c<num_bytes;c++)
                                    length+=length_bytes[c]<<(8*(num_bytes-1-c));

                                message->length=length;
                                read_message_content(message);
                            }
                            else {
                                if(onerror)
                                    onerror(ec);
                            }
                        });
                    }
                    else {
                        message->length=length;
                        read_message_content(message);
                    }
                }
                else {
                    if(onerror)
                        onerror(ec);
                }
            });
        }
        
        void read_message_content(std::shared_ptr<Message> message) {
            boost::asio::async_read(*connection->socket, message->streambuf, boost::asio::transfer_exactly(message->length), 
                    [this, message]
                    (const boost::system::error_code& ec, size_t bytes_transferred) {
                if(!ec) {
                    //If connection close
                    if((message->fin_rsv_opcode&0x0f)==8) {
                        int status=0;
                        if(message->length>=2) {
                            unsigned char byte1=message->get();
                            unsigned char byte2=message->get();
                            status=(byte1<<8)+byte2;
                        }
                        
                        auto reason=message->string();
                        
                        send_close(status, reason);
                        if(onclose)
                            onclose(status, reason);
                        return;
                    }
                    //If ping
                    else if((message->fin_rsv_opcode&0x0f)==9) {
                        //send pong
                        auto empty_send_stream=std::make_shared<SendStream>();
                        send(empty_send_stream, nullptr, message->fin_rsv_opcode+1);
                    }
                    else if(onmessage) {
                        onmessage(message);
                    }

                    //Next message
                    std::shared_ptr<Message> next_message(new Message());
                    read_message(next_message);
                }
                else {
                    if(onerror)
                        onerror(ec);
                }
            });
        }
    };
    
    template<class socket_type>
    class SocketClient : public SocketClientBase<socket_type> {};
    
    typedef boost::asio::ip::tcp::socket WS;
    
    template<>
    class SocketClient<WS> : public SocketClientBase<WS> {
    public:
        SocketClient(const std::string& server_port_path) : SocketClientBase<WS>::SocketClientBase(server_port_path, 80) {};
        
    private:
        void connect() {
            boost::asio::ip::tcp::resolver::query query(host, std::to_string(port));
            
            asio_resolver.async_resolve(query, [this]
                    (const boost::system::error_code &ec, boost::asio::ip::tcp::resolver::iterator it){
                if(!ec) {
                    connection=std::unique_ptr<Connection>(new Connection(new WS(asio_io_service)));

                    boost::asio::async_connect(*connection->socket, it, [this]
                            (const boost::system::error_code &ec, boost::asio::ip::tcp::resolver::iterator it){
                        if(!ec) {
                            handshake();
                        }
                        else
                            throw std::invalid_argument(ec.message());
                    });
                }
                else
                    throw std::invalid_argument(ec.message());
            });
        }
    };
}

#endif	/* CLIENT_WS_HPP */
