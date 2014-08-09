#ifndef CLIENT_WS_HPP
#define	CLIENT_WS_HPP

#include "crypto.hpp"

#include <boost/asio.hpp>

#include <unordered_map>
#include <iostream>
#include <regex>
#include <random>

namespace SimpleWeb {
    template <class socket_type>
    class SocketClientBase {
    public:
        class Connection {
            friend class SocketClientBase<socket_type>;

        public:
            std::unordered_map<std::string, std::string> header;
            
            Connection(std::shared_ptr<socket_type> socket): socket(socket), closed(false) {}
        private:
            std::shared_ptr<socket_type> socket;
            
            std::atomic<bool> closed;
        };
        
        std::shared_ptr<Connection> connection;
        
        std::function<void(void)> onopen;
        std::function<void(std::shared_ptr<std::istream>, size_t)> onmessage;
        std::function<void(const boost::system::error_code&)> onerror;
        std::function<void(int)> onclose;
        
        void start() {
            connect();
            
            asio_io_service.run();
        }
        
        void send(std::iostream& stream, const std::function<void(const boost::system::error_code&)>& callback=nullptr, 
                unsigned char message_header=129) {
            //Create mask
            std::vector<unsigned char> mask;
            mask.resize(4);
            std::uniform_int_distribution<unsigned char> dist;
            std::random_device rd;
            for(int c=0;c<4;c++) {
                mask[c]=dist(rd);
            }

            std::shared_ptr<boost::asio::streambuf> write_buffer(new boost::asio::streambuf);
            std::ostream response(write_buffer.get());
            
            stream.seekp(0, std::ios::end);
            size_t length=stream.tellp();
            stream.seekp(0, std::ios::beg);
            
            response.put(message_header);
            //masked (first length byte>=128)
            if(length>=126) {
                int num_bytes;
                if(length>0xffff) {
                    num_bytes=8;
                    response.put(127+128);
                }
                else {
                    num_bytes=2;
                    response.put(126+128);
                }
                
                for(int c=num_bytes-1;c>=0;c--) {
                    response.put((length>>(8*c))%256);
                }
            }
            else
                response.put(length+128);
            
            for(int c=0;c<4;c++) {
                response.put(mask[c]);
            }
            
            for(size_t c=0;c<length;c++) {
                response.put(stream.get()^mask[c%4]);
            }
            
            //Need to copy the callback-function in case its destroyed
            boost::asio::async_write(*connection->socket, *write_buffer, 
                    [this, write_buffer, callback](const boost::system::error_code& ec, size_t bytes_transferred) {
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
            
            std::stringstream response;
            
            response.put(status>>8);
            response.put(status%256);
            
            response << reason;

            //message_header=136: message close
            send(response, [](const boost::system::error_code& ec){}, 136);
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
            std::regex e("^([^:/]+):?([0-9]*)(.*)$");

            std::smatch sm;

            if(std::regex_match(host_port_path, sm, e)) {
                host=sm[1];
                path=sm[3];
                port=default_port;
                if(sm[2]!="")
                    port=(unsigned short)std::stoul(sm[2]);
                asio_endpoint=boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port);
            }
            else {
                throw std::invalid_argument("Error parsing host_port_path");
            }
        }
        
        virtual void connect()=0;
        
        void handshake(std::shared_ptr<socket_type> socket) {
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
            
            boost::asio::async_write(*socket, *write_buffer, 
                    [this, socket, write_buffer, accept_sha1]
                    (const boost::system::error_code& ec, size_t bytes_transferred) {
                if(!ec) {
                    std::shared_ptr<boost::asio::streambuf> read_buffer(new boost::asio::streambuf);

                    boost::asio::async_read_until(*socket, *read_buffer, "\r\n\r\n",
                            [this, socket, read_buffer, accept_sha1]
                            (const boost::system::error_code& ec, size_t bytes_transferred) {
                        if(!ec) {
                            //Convert to istream to extract string-lines
                            std::istream stream(read_buffer.get());
                            
                            connection=std::make_shared<Connection>(socket);
                            parse_handshake(stream);
                            if(Crypto::Base64::decode(connection->header["Sec-WebSocket-Accept"])==*accept_sha1) {
                                if(onopen)
                                    onopen();
                                read_message(read_buffer);
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
            std::smatch sm;

            //Not parsing the first line
            std::string line;
            getline(stream, line);
            line.pop_back();

            bool matched;
            std::regex e("^([^:]*): ?(.*)$");
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
        
        void read_message(std::shared_ptr<boost::asio::streambuf> read_buffer) {
            boost::asio::async_read(*connection->socket, *read_buffer, boost::asio::transfer_exactly(2),
                    [this, read_buffer](const boost::system::error_code& ec, size_t bytes_transferred) {
                if(!ec) {
                    std::istream stream(read_buffer.get());

                    std::vector<unsigned char> num_bytes;
                    num_bytes.resize(2);
                    stream.read((char*)&num_bytes[0], 2);
                    
                    unsigned char opcode=(num_bytes[0]&0x0f);
                    
                    size_t length=(num_bytes[1]&127);

                    if(length==126) {
                        //2 next bytes is the size of content
                        boost::asio::async_read(*connection->socket, *read_buffer, boost::asio::transfer_exactly(2),
                                [this, read_buffer, opcode]
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
                                
                                read_message_content(read_buffer, length, opcode);
                            }
                            else {
                                if(onerror)
                                    onerror(ec);
                            }
                        });
                    }
                    else if(length==127) {
                        //8 next bytes is the size of content
                        boost::asio::async_read(*connection->socket, *read_buffer, boost::asio::transfer_exactly(8),
                                [this, read_buffer, opcode]
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

                                read_message_content(read_buffer, length, opcode);
                            }
                            else {
                                if(onerror)
                                    onerror(ec);
                            }
                        });
                    }
                    else
                        read_message_content(read_buffer, length, opcode);
                }
                else {
                    if(onerror)
                        onerror(ec);
                }
            });
        }
        
        void read_message_content(std::shared_ptr<boost::asio::streambuf> read_buffer, size_t length, unsigned char opcode) {
            boost::asio::async_read(*connection->socket, *read_buffer, boost::asio::transfer_exactly(length),
                    [this, read_buffer, length, opcode]
                    (const boost::system::error_code& ec, size_t bytes_transferred) {
                if(!ec) {
                    std::shared_ptr<std::istream> message(new std::istream(read_buffer.get()));
                    
                    //If connection closed
                    if(opcode==8) {
                        int status=0;
                        if(length>=2) {
                            unsigned char byte1=message->get();
                            unsigned char byte2=message->get();
                            status=(byte1<<8)+byte2;
                        }
                        
                        send_close(status);
                        if(onclose)
                            onclose(status);
                        return;
                    }

                    if(onmessage)
                        onmessage(message, length);

                    //Next message
                    read_message(read_buffer);
                }
                else {
                    if(onerror)
                        onerror(ec);
                }
            });
        }
    };
    
    template<class socket_type>
    class Client : public SocketClientBase<socket_type> {};
    
    typedef boost::asio::ip::tcp::socket WS;
    
    template<>
    class Client<WS> : public SocketClientBase<WS> {
    public:
        Client(const std::string& server_port_path) : SocketClientBase<WS>::SocketClientBase(server_port_path, 80) {};
        
    private:
        void connect() {
            boost::asio::ip::tcp::resolver::query query(host, std::to_string(port));
            
            asio_resolver.async_resolve(query, [this]
                    (const boost::system::error_code &ec, boost::asio::ip::tcp::resolver::iterator it){
                if(!ec) {
                    std::shared_ptr<WS> socket(new WS(asio_io_service));

                    boost::asio::async_connect(*socket, it, [this, socket]
                            (const boost::system::error_code &ec, boost::asio::ip::tcp::resolver::iterator it){
                        if(!ec) {
                            handshake(socket);
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