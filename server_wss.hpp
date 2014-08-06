#ifndef SERVER_WSS_HPP
#define	SERVER_WSS_HPP

#include "server_ws.hpp"
#include <boost/asio/ssl.hpp>

namespace SimpleWeb {
    typedef boost::asio::ssl::stream<boost::asio::ip::tcp::socket> WSS;    
    
    template<>
    class Server<WSS> : public SocketServerBase<WSS> {
    public:
        Server(unsigned short port, size_t num_threads, const std::string& cert_file, const std::string& private_key_file, 
                size_t timeout_request=5, size_t timeout_idle=0) : 
                SocketServerBase<WSS>::SocketServerBase(port, num_threads, timeout_request, timeout_idle), 
                context(boost::asio::ssl::context::sslv23) {
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
                    //Set timeout on the following boost::asio::ssl::stream::async_handshake
                    std::shared_ptr<boost::asio::deadline_timer> timer;
                    if(timeout_request>0)
                        timer=set_timeout_on_socket(socket, timeout_request);
                    (*socket).async_handshake(boost::asio::ssl::stream_base::server, 
                            [this, socket, timer](const boost::system::error_code& ec) {
                        if(timeout_request>0)
                            timer->cancel();
                        if(!ec) {
                            process_request_and_start_connection(socket);
                        }
                    });
                }
            });
        }
        
        std::shared_ptr<boost::asio::deadline_timer> set_timeout_on_socket(std::shared_ptr<WSS> socket, size_t seconds) {
            std::shared_ptr<boost::asio::deadline_timer> timer(new boost::asio::deadline_timer(m_io_service));
            timer->expires_from_now(boost::posix_time::seconds(seconds));
            timer->async_wait([socket](const boost::system::error_code& ec){
                if(!ec) {
                    socket->lowest_layer().shutdown(boost::asio::ip::tcp::socket::shutdown_both);
                    socket->lowest_layer().close();
                }
            });
            return timer;
        }
    };
}


#endif	/* SERVER_WSS_HPP */

