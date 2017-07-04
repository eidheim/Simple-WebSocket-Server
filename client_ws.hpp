#ifndef CLIENT_WS_HPP
#define CLIENT_WS_HPP

#include "crypto.hpp"
#include "utility.hpp"

#include <boost/algorithm/string/predicate.hpp>
#include <boost/asio.hpp>
#include <boost/functional/hash.hpp>

#include <atomic>
#include <iostream>
#include <list>
#include <random>

#ifdef USE_STANDALONE_ASIO
#include <asio.hpp>
namespace SimpleWeb {
  using error_code = std::error_code;
  using errc = std::errc;
  namespace make_error_code = std;
} // namespace SimpleWeb
#else
#include <boost/asio.hpp>
namespace SimpleWeb {
  namespace asio = boost::asio;
  using error_code = boost::system::error_code;
  namespace errc = boost::system::errc;
  namespace make_error_code = boost::system::errc;
} // namespace SimpleWeb
#endif

namespace SimpleWeb {
// TODO: remove when onopen, onmessage, etc is removed:
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#elif defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996)
#endif

  template <class socket_type>
  class SocketClient;

  template <class socket_type>
  class SocketClientBase {
  public:
    virtual ~SocketClientBase() {}

    class SendStream : public std::iostream {
      friend class SocketClientBase<socket_type>;

    private:
      asio::streambuf streambuf;

    public:
      SendStream() : std::iostream(&streambuf) {}
      size_t size() {
        return streambuf.size();
      }
    };

    class Message;

    class Connection {
      friend class SocketClientBase<socket_type>;
      friend class SocketClient<socket_type>;

    public:
      CaseInsensitiveMultimap header;
      std::string remote_endpoint_address;
      unsigned short remote_endpoint_port;

    private:
      Connection(socket_type *socket) : socket(socket), strand(socket->get_io_service()), closed(false) {}

      std::unique_ptr<socket_type> socket;
      std::shared_ptr<Message> message;

      void parse_handshake() {
        std::string line;
        getline(*message, line);
        //Not parsing the first line

        getline(*message, line);
        size_t param_end;
        while((param_end = line.find(':')) != std::string::npos) {
          size_t value_start = param_end + 1;
          if((value_start) < line.size()) {
            if(line[value_start] == ' ')
              value_start++;
            if(value_start < line.size())
              header.emplace(line.substr(0, param_end), line.substr(value_start, line.size() - value_start - 1));
          }

          getline(*message, line);
        }
      }

      asio::strand strand;

      class SendData {
      public:
        SendData(const std::shared_ptr<SendStream> &send_stream, const std::function<void(const error_code)> &callback)
            : send_stream(send_stream), callback(callback) {}
        std::shared_ptr<SendStream> send_stream;
        std::function<void(const error_code)> callback;
      };

      std::list<SendData> send_queue;

      void send_from_queue() {
        strand.post([this]() {
          asio::async_write(*socket, send_queue.begin()->send_stream->streambuf, strand.wrap([this](const error_code &ec, size_t /*bytes_transferred*/) {
            auto send_queued = send_queue.begin();
            if(send_queued->callback)
              send_queued->callback(ec);
            if(!ec) {
              send_queue.erase(send_queued);
              if(send_queue.size() > 0)
                send_from_queue();
            }
            else
              send_queue.clear();
          }));
        });
      }

      std::atomic<bool> closed;

      void read_remote_endpoint_data() {
        try {
          remote_endpoint_address = socket->lowest_layer().remote_endpoint().address().to_string();
          remote_endpoint_port = socket->lowest_layer().remote_endpoint().port();
        }
        catch(const std::exception &e) {
          std::cerr << e.what() << std::endl;
        }
      }
    };

    class Message : public std::istream {
      friend class SocketClientBase<socket_type>;
      friend class Connection;

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
      Message() : std::istream(&streambuf) {}
      size_t length;
      asio::streambuf streambuf;
    };

    DEPRECATED std::function<void(void)> onopen;
    std::function<void(void)> on_open;
    DEPRECATED std::function<void(std::shared_ptr<Message>)> onmessage;
    std::function<void(std::shared_ptr<Message>)> on_message;
    DEPRECATED std::function<void(int, const std::string &)> onclose;
    std::function<void(int, const std::string &)> on_close;
    DEPRECATED std::function<void(const error_code &)> onerror;
    std::function<void(const error_code &)> on_error;

    void start() {
      // TODO: remove when onopen, onmessage, etc is removed:
      if(onopen)
        on_open = onopen;
      if(onmessage)
        on_message = onmessage;
      if(onclose)
        on_close = onclose;
      if(onerror)
        on_error = onerror;

      if(!io_service) {
        io_service = std::make_shared<asio::io_service>();
        internal_io_service = true;
      }

      if(io_service->stopped())
        io_service->reset();

      if(!resolver)
        resolver = std::unique_ptr<asio::ip::tcp::resolver>(new asio::ip::tcp::resolver(*io_service));

      connect();

      if(internal_io_service)
        io_service->run();
    }

    void stop() {
      resolver->cancel();
      if(internal_io_service)
        io_service->stop();

      if(current_connection) {
        error_code ec;
        current_connection->socket->lowest_layer().shutdown(asio::ip::tcp::socket::shutdown_both, ec);
        current_connection->socket->lowest_layer().close();
      }
    }

    ///fin_rsv_opcode: 129=one fragment, text, 130=one fragment, binary, 136=close connection.
    ///See http://tools.ietf.org/html/rfc6455#section-5.2 for more information
    void send(const std::shared_ptr<SendStream> &message_stream, const std::function<void(const error_code &)> &callback = nullptr,
              unsigned char fin_rsv_opcode = 129) {
      //Create mask
      std::vector<unsigned char> mask;
      mask.resize(4);
      std::uniform_int_distribution<unsigned short> dist(0, 255);
      std::random_device rd;
      for(int c = 0; c < 4; c++) {
        mask[c] = static_cast<unsigned char>(dist(rd));
      }

      auto send_stream = std::make_shared<SendStream>();

      size_t length = message_stream->size();

      send_stream->put(fin_rsv_opcode);
      //masked (first length byte>=128)
      if(length >= 126) {
        int num_bytes;
        if(length > 0xffff) {
          num_bytes = 8;
          send_stream->put(static_cast<unsigned char>(127 + 128));
        }
        else {
          num_bytes = 2;
          send_stream->put(static_cast<unsigned char>(126 + 128));
        }

        for(int c = num_bytes - 1; c >= 0; c--) {
          send_stream->put((static_cast<unsigned long long>(length) >> (8 * c)) % 256);
        }
      }
      else
        send_stream->put(static_cast<unsigned char>(length + 128));

      for(int c = 0; c < 4; c++) {
        send_stream->put(mask[c]);
      }

      for(size_t c = 0; c < length; c++) {
        send_stream->put(message_stream->get() ^ mask[c % 4]);
      }

      current_connection->strand.post([this, send_stream, callback]() {
        current_connection->send_queue.emplace_back(send_stream, callback);
        if(current_connection->send_queue.size() == 1)
          current_connection->send_from_queue();
      });
    }

    void send_close(int status, const std::string &reason = "", const std::function<void(const error_code &)> &callback = nullptr) {
      //Send close only once (in case close is initiated by client)
      if(current_connection->closed)
        return;
      current_connection->closed = true;

      auto send_stream = std::make_shared<SendStream>();

      send_stream->put(status >> 8);
      send_stream->put(status % 256);

      *send_stream << reason;

      //fin_rsv_opcode=136: message close
      send(send_stream, callback, 136);
    }

    /// If you have your own asio::io_service, store its pointer here before running start().
    std::shared_ptr<asio::io_service> io_service;

  protected:
    bool internal_io_service = false;
    std::unique_ptr<asio::ip::tcp::resolver> resolver;

    std::string host;
    unsigned short port;
    std::string path;

    std::shared_ptr<Connection> current_connection; // TODO: remove?

    SocketClientBase(const std::string &host_port_path, unsigned short default_port) {
      size_t host_end = host_port_path.find(':');
      size_t host_port_end = host_port_path.find('/');
      if(host_end == std::string::npos) {
        host_end = host_port_end;
        port = default_port;
      }
      else {
        if(host_port_end == std::string::npos)
          port = (unsigned short)stoul(host_port_path.substr(host_end + 1));
        else
          port = (unsigned short)stoul(host_port_path.substr(host_end + 1, host_port_end - (host_end + 1)));
      }
      if(host_port_end == std::string::npos)
        path = "/";
      else
        path = host_port_path.substr(host_port_end);
      if(host_end == std::string::npos)
        host = host_port_path;
      else
        host = host_port_path.substr(0, host_end);
    }

    virtual void connect() = 0;

    void handshake(const std::shared_ptr<Connection> &connection) {
      connection->read_remote_endpoint_data();

      auto write_buffer = std::make_shared<asio::streambuf>();

      std::ostream request(write_buffer.get());

      request << "GET " << path << " HTTP/1.1"
              << "\r\n";
      request << "Host: " << host << "\r\n";
      request << "Upgrade: websocket\r\n";
      request << "Connection: Upgrade\r\n";

      //Make random 16-byte nonce
      std::string nonce;
      nonce.resize(16);
      std::uniform_int_distribution<unsigned short> dist(0, 255);
      std::random_device rd;
      for(int c = 0; c < 16; c++)
        nonce[c] = static_cast<unsigned char>(dist(rd));

      auto nonce_base64 = std::make_shared<std::string>(Crypto::Base64::encode(nonce));
      request << "Sec-WebSocket-Key: " << *nonce_base64 << "\r\n";
      request << "Sec-WebSocket-Version: 13\r\n";
      request << "\r\n";

      connection->message = std::shared_ptr<Message>(new Message());

      asio::async_write(*connection->socket, *write_buffer, [this, connection, write_buffer, nonce_base64](const error_code &ec, size_t /*bytes_transferred*/) {
        if(!ec) {
          asio::async_read_until(*connection->socket, connection->message->streambuf, "\r\n\r\n", [this, connection, nonce_base64](const error_code &ec, size_t /*bytes_transferred*/) {
            if(!ec) {
              connection->parse_handshake();
              auto header_it = connection->header.find("Sec-WebSocket-Accept");
              static auto ws_magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
              if(header_it != connection->header.end() &&
                 Crypto::Base64::decode(header_it->second) == Crypto::sha1(*nonce_base64 + ws_magic_string)) {
                if(on_open)
                  on_open();
                read_message(connection);
              }
              else if(on_error)
                on_error(make_error_code::make_error_code(errc::protocol_error));
            }
            else if(on_error)
              on_error(ec);
          });
        }
        else if(on_error)
          on_error(ec);
      });
    }

    void read_message(const std::shared_ptr<Connection> &connection) {
      asio::async_read(*connection->socket, connection->message->streambuf, asio::transfer_exactly(2), [this, connection](const error_code &ec, size_t bytes_transferred) {
        if(!ec) {
          if(bytes_transferred == 0) { //TODO: This might happen on server at least, might also happen here
            read_message(connection);
            return;
          }
          std::vector<unsigned char> first_bytes;
          first_bytes.resize(2);
          connection->message->read((char *)&first_bytes[0], 2);

          connection->message->fin_rsv_opcode = first_bytes[0];

          //Close connection if masked message from server (protocol error)
          if(first_bytes[1] >= 128) {
            const std::string reason("message from server masked");
            auto kept_connection = connection;
            send_close(1002, reason, [this, kept_connection](const error_code & /*ec*/) {});
            if(on_close)
              on_close(1002, reason);
            return;
          }

          size_t length = (first_bytes[1] & 127);

          if(length == 126) {
            //2 next bytes is the size of content
            asio::async_read(*connection->socket, connection->message->streambuf, asio::transfer_exactly(2), [this, connection](const error_code &ec, size_t /*bytes_transferred*/) {
              if(!ec) {
                std::vector<unsigned char> length_bytes;
                length_bytes.resize(2);
                connection->message->read((char *)&length_bytes[0], 2);

                size_t length = 0;
                int num_bytes = 2;
                for(int c = 0; c < num_bytes; c++)
                  length += length_bytes[c] << (8 * (num_bytes - 1 - c));

                connection->message->length = length;
                read_message_content(connection);
              }
              else if(on_error)
                on_error(ec);
            });
          }
          else if(length == 127) {
            //8 next bytes is the size of content
            asio::async_read(*connection->socket, connection->message->streambuf, asio::transfer_exactly(8), [this, connection](const error_code &ec, size_t /*bytes_transferred*/) {
              if(!ec) {
                std::vector<unsigned char> length_bytes;
                length_bytes.resize(8);
                connection->message->read((char *)&length_bytes[0], 8);

                size_t length = 0;
                int num_bytes = 8;
                for(int c = 0; c < num_bytes; c++)
                  length += length_bytes[c] << (8 * (num_bytes - 1 - c));

                connection->message->length = length;
                read_message_content(connection);
              }
              else if(on_error)
                on_error(ec);
            });
          }
          else {
            connection->message->length = length;
            read_message_content(connection);
          }
        }
        else if(on_error)
          on_error(ec);
      });
    }

    void read_message_content(const std::shared_ptr<Connection> &connection) {
      asio::async_read(*connection->socket, connection->message->streambuf, asio::transfer_exactly(connection->message->length), [this, connection](const error_code &ec, size_t /*bytes_transferred*/) {
        if(!ec) {
          //If connection close
          if((connection->message->fin_rsv_opcode & 0x0f) == 8) {
            int status = 0;
            if(connection->message->length >= 2) {
              unsigned char byte1 = connection->message->get();
              unsigned char byte2 = connection->message->get();
              status = (byte1 << 8) + byte2;
            }

            auto reason = connection->message->string();
            auto kept_connection = connection;
            send_close(status, reason, [this, kept_connection](const error_code & /*ec*/) {});
            if(on_close)
              on_close(status, reason);
            return;
          }
          //If ping
          else if((connection->message->fin_rsv_opcode & 0x0f) == 9) {
            //send pong
            auto empty_send_stream = std::make_shared<SendStream>();
            send(empty_send_stream, nullptr, connection->message->fin_rsv_opcode + 1);
          }
          else if(on_message) {
            on_message(connection->message);
          }

          //Next message
          connection->message = std::shared_ptr<Message>(new Message());
          read_message(connection);
        }
        else if(on_error)
          on_error(ec);
      });
    }
  };

  template <class socket_type>
  class SocketClient : public SocketClientBase<socket_type> {};

  typedef asio::ip::tcp::socket WS;

  template <>
  class SocketClient<WS> : public SocketClientBase<WS> {
  public:
    SocketClient(const std::string &server_port_path) : SocketClientBase<WS>::SocketClientBase(server_port_path, 80){};

  protected:
    void connect() {
      asio::ip::tcp::resolver::query query(host, std::to_string(port));

      resolver->async_resolve(query, [this](const error_code &ec, asio::ip::tcp::resolver::iterator it) {
        if(!ec) {
          auto connection = std::shared_ptr<Connection>(new Connection(new WS(*io_service)));
          this->current_connection = connection;

          asio::async_connect(*connection->socket, it, [this, connection](const error_code &ec, asio::ip::tcp::resolver::iterator /*it*/) {
            if(!ec) {
              asio::ip::tcp::no_delay option(true);
              connection->socket->set_option(option);

              handshake(connection);
            }
            else if(on_error)
              on_error(ec);
          });
        }
        else if(on_error)
          on_error(ec);
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

#endif /* CLIENT_WS_HPP */
