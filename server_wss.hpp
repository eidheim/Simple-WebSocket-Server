#ifndef SERVER_WSS_HPP
#define	SERVER_WSS_HPP

#include "server_ws.hpp"
#include <boost/asio/ssl.hpp>

namespace SimpleWeb {
    typedef boost::asio::ssl::stream<boost::asio::ip::tcp::socket> WSS;    
    
    template<>
    class Server<WSS> : public SocketServerBase<WSS> {
    public:
        Server(unsigned short port, size_t num_threads, const std::string& cert_file, const std::string& private_key_file) : 
                SocketServerBase<WSS>::SocketServerBase(port, num_threads), context(boost::asio::ssl::context::sslv23) {
            context.use_certificate_chain_file(cert_file);
            context.use_private_key_file(private_key_file, boost::asio::ssl::context::pem);
        }

    private:
        boost::asio::ssl::context context;
        
        void accept() {
            //Create new socket for this connection
            //Shared_ptr is used to pass temporary objects to the asynchronous functions
            std::shared_ptr<WSS> socket(new WSS(m_io_service, context));

            acceptor.async_accept((*socket).lowest_layer(), [this, socket](const boost::system::error_code& ec) {
                //Immediately start accepting a new connection
                accept();

                if(!ec) {
                    (*socket).async_handshake(boost::asio::ssl::stream_base::server, 
                            [this, socket](const boost::system::error_code& ec) {
                        if(!ec) {
                            process_request_and_start_connection(socket);
                        }
                    });
                }
            });
        }
    };
}


#endif	/* SERVER_WSS_HPP */

