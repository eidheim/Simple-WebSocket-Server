#ifndef CLIENT_WSS_HPP
#define	CLIENT_WSS_HPP

#include "client_ws.hpp"
#include <boost/asio/ssl.hpp>

namespace SimpleWeb {
    typedef boost::asio::ssl::stream<boost::asio::ip::tcp::socket> WSS;    
    
    template<>
    class SocketClient<WSS> : public SocketClientBase<WSS> {
    public:
        SocketClient(const std::string& server_port_path, bool verify_certificate=true) : SocketClientBase<WSS>::SocketClientBase(server_port_path, 443),
                asio_context(boost::asio::ssl::context::sslv23) {
            if(verify_certificate)
                asio_context.set_verify_mode(boost::asio::ssl::verify_peer);
            else
                asio_context.set_verify_mode(boost::asio::ssl::verify_none);
        };

    private:
        boost::asio::ssl::context asio_context;
        
        void connect() {
            boost::asio::ip::tcp::resolver::query query(host, std::to_string(port));
            
            asio_resolver.async_resolve(query, [this]
                    (const boost::system::error_code &ec, boost::asio::ip::tcp::resolver::iterator it){
                if(!ec) {
                    connection=std::unique_ptr<Connection>(new Connection(new WSS(asio_io_service, asio_context)));
                    
                    boost::asio::async_connect(connection->socket->lowest_layer(), it, [this]
                            (const boost::system::error_code &ec, boost::asio::ip::tcp::resolver::iterator it){
                        if(!ec) {
                            connection->socket->async_handshake(boost::asio::ssl::stream_base::client, 
                                    [this](const boost::system::error_code& ec) {
                                if(!ec)
                                    handshake();
                                else
                                    throw std::invalid_argument(ec.message());
                            });
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

#endif	/* CLIENT_WSS_HPP */