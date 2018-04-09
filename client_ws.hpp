#ifndef CLIENT_WS_HPP
#define CLIENT_WS_HPP

#include "crypto.hpp"
#include "utility.hpp"

#include <array>
#include <atomic>
#include <iostream>
#include <limits>
#include <list>
#include <mutex>
#include <random>

#ifdef USE_STANDALONE_ASIO
#include <asio.hpp>
#include <asio/steady_timer.hpp>
namespace SimpleWeb {
  using error_code = std::error_code;
  using errc = std::errc;
  namespace make_error_code = std;
} // namespace SimpleWeb
#else
#include <boost/asio.hpp>
#include <boost/asio/steady_timer.hpp>
namespace SimpleWeb {
  namespace asio = boost::asio;
  using error_code = boost::system::error_code;
  namespace errc = boost::system::errc;
  namespace make_error_code = boost::system::errc;
} // namespace SimpleWeb
#endif

namespace SimpleWeb {
  template <class socket_type>
  class SocketClient;

  template <class socket_type>
  class SocketClientBase {
  public:
    class Message : public std::istream {
      friend class SocketClientBase<socket_type>;
      friend class Connection;

    public:
      unsigned char fin_rsv_opcode;
      std::size_t size() noexcept {
        return length;
      }

      /// Convenience function to return std::string. The stream buffer is consumed.
      std::string string() noexcept {
        try {
          std::stringstream ss;
          ss << rdbuf();
          return ss.str();
        }
        catch(...) {
          return std::string();
        }
      }

    private:
      Message() noexcept : std::istream(&streambuf), length(0) {}
      Message(unsigned char fin_rsv_opcode, std::size_t length) noexcept : std::istream(&streambuf), fin_rsv_opcode(fin_rsv_opcode), length(length) {}
      std::size_t length;
      asio::streambuf streambuf;
    };

    /// The buffer is consumed during send operations.
    class SendStream : public std::iostream {
      friend class SocketClientBase<socket_type>;

      asio::streambuf streambuf;

    public:
      SendStream() noexcept : std::iostream(&streambuf) {}

      /// Returns the size of the buffer
      std::size_t size() const noexcept {
        return streambuf.size();
      }
    };

    class Connection : public std::enable_shared_from_this<Connection> {
      friend class SocketClientBase<socket_type>;
      friend class SocketClient<socket_type>;

    public:
      std::string http_version, status_code;
      CaseInsensitiveMultimap header;

      asio::ip::tcp::endpoint remote_endpoint;

      std::string remote_endpoint_address() noexcept {
        try {
          return remote_endpoint.address().to_string();
        }
        catch(...) {
          return std::string();
        }
      }

      unsigned short remote_endpoint_port() noexcept {
        return remote_endpoint.port();
      }

    private:
      template <typename... Args>
      Connection(std::shared_ptr<ScopeRunner> handler_runner, long timeout_idle, Args &&... args) noexcept
          : handler_runner(std::move(handler_runner)), socket(new socket_type(std::forward<Args>(args)...)), timeout_idle(timeout_idle), strand(socket->get_io_service()), closed(false) {}

      std::shared_ptr<ScopeRunner> handler_runner;

      std::unique_ptr<socket_type> socket; // Socket must be unique_ptr since asio::ssl::stream<asio::ip::tcp::socket> is not movable
      std::mutex socket_close_mutex;

      std::shared_ptr<Message> message;
      std::shared_ptr<Message> fragmented_message;

      long timeout_idle;
      std::unique_ptr<asio::steady_timer> timer;
      std::mutex timer_mutex;

      void close() noexcept {
        error_code ec;
        std::unique_lock<std::mutex> lock(socket_close_mutex); // The following operations seems to be needed to run sequentially
        socket->lowest_layer().shutdown(asio::ip::tcp::socket::shutdown_both, ec);
        socket->lowest_layer().close(ec);
      }

      void set_timeout(long seconds = -1) noexcept {
        bool use_timeout_idle = false;
        if(seconds == -1) {
          use_timeout_idle = true;
          seconds = timeout_idle;
        }

        std::unique_lock<std::mutex> lock(timer_mutex);

        if(seconds == 0) {
          timer = nullptr;
          return;
        }

        timer = std::unique_ptr<asio::steady_timer>(new asio::steady_timer(socket->get_io_service()));
        timer->expires_from_now(std::chrono::seconds(seconds));
        std::weak_ptr<Connection> connection_weak(this->shared_from_this()); // To avoid keeping Connection instance alive longer than needed
        timer->async_wait([connection_weak, use_timeout_idle](const error_code &ec) {
          if(!ec) {
            if(auto connection = connection_weak.lock()) {
              if(use_timeout_idle)
                connection->send_close(1000, "idle timeout"); // 1000=normal closure
              else
                connection->close();
            }
          }
        });
      }

      void cancel_timeout() noexcept {
        std::unique_lock<std::mutex> lock(timer_mutex);
        if(timer) {
          error_code ec;
          timer->cancel(ec);
        }
      }

      asio::io_service::strand strand;

      class SendData {
      public:
        SendData(std::shared_ptr<SendStream> send_stream, std::function<void(const error_code)> &&callback) noexcept
            : send_stream(std::move(send_stream)), callback(std::move(callback)) {}
        std::shared_ptr<SendStream> send_stream;
        std::function<void(const error_code)> callback;
      };

      std::list<SendData> send_queue;

      void send_from_queue() {
        auto self = this->shared_from_this();
        strand.post([self]() {
          asio::async_write(*self->socket, self->send_queue.begin()->send_stream->streambuf, self->strand.wrap([self](const error_code &ec, std::size_t /*bytes_transferred*/) {
            auto lock = self->handler_runner->continue_lock();
            if(!lock)
              return;
            auto send_queued = self->send_queue.begin();
            if(send_queued->callback)
              send_queued->callback(ec);
            if(!ec) {
              self->send_queue.erase(send_queued);
              if(self->send_queue.size() > 0)
                self->send_from_queue();
            }
            else
              self->send_queue.clear();
          }));
        });
      }

      std::atomic<bool> closed;

      void read_remote_endpoint() noexcept {
        try {
          remote_endpoint = socket->lowest_layer().remote_endpoint();
        }
        catch(const std::exception &e) {
          std::cerr << e.what() << std::endl;
        }
      }

    public:
      /// fin_rsv_opcode: 129=one fragment, text, 130=one fragment, binary, 136=close connection.
      /// See http://tools.ietf.org/html/rfc6455#section-5.2 for more information
      void send(const std::shared_ptr<SendStream> &send_stream, const std::function<void(const error_code &)> &callback = nullptr,
                unsigned char fin_rsv_opcode = 129) {
        cancel_timeout();
        set_timeout();

        // Create mask
        std::array<unsigned char, 4> mask;
        std::uniform_int_distribution<unsigned short> dist(0, 255);
        std::random_device rd;
        for(std::size_t c = 0; c < 4; c++)
          mask[c] = static_cast<unsigned char>(dist(rd));

        auto message_stream = std::make_shared<SendStream>();

        std::size_t length = send_stream->size();

        message_stream->put(static_cast<char>(fin_rsv_opcode));
        // Masked (first length byte>=128)
        if(length >= 126) {
          std::size_t num_bytes;
          if(length > 0xffff) {
            num_bytes = 8;
            message_stream->put(static_cast<char>(127 + 128));
          }
          else {
            num_bytes = 2;
            message_stream->put(static_cast<char>(126 + 128));
          }

          for(std::size_t c = num_bytes - 1; c != static_cast<std::size_t>(-1); c--)
            message_stream->put((static_cast<unsigned long long>(length) >> (8 * c)) % 256);
        }
        else
          message_stream->put(static_cast<char>(length + 128));

        for(std::size_t c = 0; c < 4; c++)
          message_stream->put(static_cast<char>(mask[c]));

        for(std::size_t c = 0; c < length; c++)
          message_stream->put(send_stream->get() ^ mask[c % 4]);

        auto self = this->shared_from_this();
        strand.post([self, message_stream, callback]() {
          self->send_queue.emplace_back(message_stream, callback);
          if(self->send_queue.size() == 1)
            self->send_from_queue();
        });
      }

      void send_close(int status, const std::string &reason = "", const std::function<void(const error_code &)> &callback = nullptr) {
        // Send close only once (in case close is initiated by client)
        if(closed)
          return;
        closed = true;

        auto send_stream = std::make_shared<SendStream>();

        send_stream->put(status >> 8);
        send_stream->put(status % 256);

        *send_stream << reason;

        // fin_rsv_opcode=136: message close
        send(send_stream, callback, 136);
      }
    };

    class Config {
      friend class SocketClientBase<socket_type>;

    private:
      Config() noexcept {}

    public:
      /// Timeout on request handling. Defaults to no timeout.
      long timeout_request = 0;
      /// Idle timeout. Defaults to no timeout.
      long timeout_idle = 0;
      /// Maximum size of incoming messages. Defaults to architecture maximum.
      /// Exceeding this limit will result in a message_size error code and the connection will be closed.
      std::size_t max_message_size = std::numeric_limits<std::size_t>::max();
      /// Additional header fields to send when performing WebSocket handshake.
      /// Use this variable to for instance set Sec-WebSocket-Protocol.
      CaseInsensitiveMultimap header;
    };
    /// Set before calling start().
    Config config;

    std::function<void(std::shared_ptr<Connection>)> on_open;
    std::function<void(std::shared_ptr<Connection>, std::shared_ptr<Message>)> on_message;
    std::function<void(std::shared_ptr<Connection>, int, const std::string &)> on_close;
    std::function<void(std::shared_ptr<Connection>, const error_code &)> on_error;
    std::function<void(std::shared_ptr<Connection>)> on_ping;
    std::function<void(std::shared_ptr<Connection>)> on_pong;

    void start() {
      if(!io_service) {
        io_service = std::make_shared<asio::io_service>();
        internal_io_service = true;
      }

      if(io_service->stopped())
        io_service->reset();

      connect();

      if(internal_io_service)
        io_service->run();
    }

    void stop() noexcept {
      {
        std::unique_lock<std::mutex> lock(connection_mutex);
        if(connection)
          connection->close();
      }

      if(internal_io_service)
        io_service->stop();
    }

    virtual ~SocketClientBase() noexcept {
      handler_runner->stop();
      stop();
    }

    /// If you have your own asio::io_service, store its pointer here before running start().
    std::shared_ptr<asio::io_service> io_service;

  protected:
    bool internal_io_service = false;

    std::string host;
    unsigned short port;
    std::string path;

    std::shared_ptr<Connection> connection;
    std::mutex connection_mutex;

    std::shared_ptr<ScopeRunner> handler_runner;

    SocketClientBase(const std::string &host_port_path, unsigned short default_port) noexcept : handler_runner(new ScopeRunner()) {
      std::size_t host_end = host_port_path.find(':');
      std::size_t host_port_end = host_port_path.find('/');
      if(host_end == std::string::npos) {
        host_end = host_port_end;
        port = default_port;
      }
      else {
        if(host_port_end == std::string::npos)
          port = static_cast<unsigned short>(stoul(host_port_path.substr(host_end + 1)));
        else
          port = static_cast<unsigned short>(stoul(host_port_path.substr(host_end + 1, host_port_end - (host_end + 1))));
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
      connection->read_remote_endpoint();

      auto write_buffer = std::make_shared<asio::streambuf>();

      std::ostream request(write_buffer.get());

      request << "GET " << path << " HTTP/1.1"
              << "\r\n";
      request << "Host: " << host << "\r\n";
      request << "Upgrade: websocket\r\n";
      request << "Connection: Upgrade\r\n";

      // Make random 16-byte nonce
      std::string nonce;
      nonce.reserve(16);
      std::uniform_int_distribution<unsigned short> dist(0, 255);
      std::random_device rd;
      for(std::size_t c = 0; c < 16; c++)
        nonce += static_cast<char>(dist(rd));

      auto nonce_base64 = std::make_shared<std::string>(Crypto::Base64::encode(nonce));
      request << "Sec-WebSocket-Key: " << *nonce_base64 << "\r\n";
      request << "Sec-WebSocket-Version: 13\r\n";
      for(auto &header_field : config.header)
        request << header_field.first << ": " << header_field.second << "\r\n";
      request << "\r\n";

      connection->message = std::shared_ptr<Message>(new Message());

      connection->set_timeout(config.timeout_request);
      asio::async_write(*connection->socket, *write_buffer, [this, connection, write_buffer, nonce_base64](const error_code &ec, std::size_t /*bytes_transferred*/) {
        connection->cancel_timeout();
        auto lock = connection->handler_runner->continue_lock();
        if(!lock)
          return;
        if(!ec) {
          connection->set_timeout(this->config.timeout_request);
          asio::async_read_until(*connection->socket, connection->message->streambuf, "\r\n\r\n", [this, connection, nonce_base64](const error_code &ec, std::size_t bytes_transferred) {
            connection->cancel_timeout();
            auto lock = connection->handler_runner->continue_lock();
            if(!lock)
              return;
            if(!ec) {
              // connection->message->streambuf.size() is not necessarily the same as bytes_transferred, from Boost-docs:
              // "After a successful async_read_until operation, the streambuf may contain additional data beyond the delimiter"
              // The chosen solution is to extract lines from the stream directly when parsing the header. What is left of the
              // streambuf (maybe some bytes of a message) is appended to in the next async_read-function
              std::size_t num_additional_bytes = connection->message->streambuf.size() - bytes_transferred;

              if(!ResponseMessage::parse(*connection->message, connection->http_version, connection->status_code, connection->header) ||
                 connection->status_code.empty() || connection->status_code.compare(0, 4, "101 ") != 0) {
                this->connection_error(connection, make_error_code::make_error_code(errc::protocol_error));
                return;
              }
              auto header_it = connection->header.find("Sec-WebSocket-Accept");
              static auto ws_magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
              if(header_it != connection->header.end() &&
                 Crypto::Base64::decode(header_it->second) == Crypto::sha1(*nonce_base64 + ws_magic_string)) {
                this->connection_open(connection);
                read_message(connection, num_additional_bytes);
              }
              else
                this->connection_error(connection, make_error_code::make_error_code(errc::protocol_error));
            }
            else
              this->connection_error(connection, ec);
          });
        }
        else
          this->connection_error(connection, ec);
      });
    }

    void read_message(const std::shared_ptr<Connection> &connection, std::size_t num_additional_bytes) {
      asio::async_read(*connection->socket, connection->message->streambuf, asio::transfer_exactly(num_additional_bytes > 2 ? 0 : 2 - num_additional_bytes), [this, connection](const error_code &ec, std::size_t bytes_transferred) {
        auto lock = connection->handler_runner->continue_lock();
        if(!lock)
          return;
        if(!ec) {
          if(bytes_transferred == 0 && connection->message->streambuf.size() == 0) { // TODO: This might happen on server at least, might also happen here
            this->read_message(connection, 0);
            return;
          }
          std::size_t num_additional_bytes = connection->message->streambuf.size() - bytes_transferred;

          std::array<unsigned char, 2> first_bytes;
          connection->message->read(reinterpret_cast<char *>(&first_bytes[0]), 2);

          connection->message->fin_rsv_opcode = first_bytes[0];

          // Close connection if masked message from server (protocol error)
          if(first_bytes[1] >= 128) {
            const std::string reason("message from server masked");
            connection->send_close(1002, reason);
            this->connection_close(connection, 1002, reason);
            return;
          }

          std::size_t length = (first_bytes[1] & 127);

          if(length == 126) {
            // 2 next bytes is the size of content
            asio::async_read(*connection->socket, connection->message->streambuf, asio::transfer_exactly(num_additional_bytes > 2 ? 0 : 2 - num_additional_bytes), [this, connection](const error_code &ec, std::size_t bytes_transferred) {
              auto lock = connection->handler_runner->continue_lock();
              if(!lock)
                return;
              if(!ec) {
                std::size_t num_additional_bytes = connection->message->streambuf.size() - bytes_transferred;

                std::array<unsigned char, 2> length_bytes;
                connection->message->read(reinterpret_cast<char *>(&length_bytes[0]), 2);

                std::size_t length = 0;
                std::size_t num_bytes = 2;
                for(std::size_t c = 0; c < num_bytes; c++)
                  length += static_cast<std::size_t>(length_bytes[c]) << (8 * (num_bytes - 1 - c));

                connection->message->length = length;
                this->read_message_content(connection, num_additional_bytes);
              }
              else
                this->connection_error(connection, ec);
            });
          }
          else if(length == 127) {
            // 8 next bytes is the size of content
            asio::async_read(*connection->socket, connection->message->streambuf, asio::transfer_exactly(num_additional_bytes > 8 ? 0 : 8 - num_additional_bytes), [this, connection](const error_code &ec, std::size_t bytes_transferred) {
              auto lock = connection->handler_runner->continue_lock();
              if(!lock)
                return;
              if(!ec) {
                std::size_t num_additional_bytes = connection->message->streambuf.size() - bytes_transferred;

                std::array<unsigned char, 8> length_bytes;
                connection->message->read(reinterpret_cast<char *>(&length_bytes[0]), 8);

                std::size_t length = 0;
                std::size_t num_bytes = 8;
                for(std::size_t c = 0; c < num_bytes; c++)
                  length += static_cast<std::size_t>(length_bytes[c]) << (8 * (num_bytes - 1 - c));

                connection->message->length = length;
                this->read_message_content(connection, num_additional_bytes);
              }
              else
                this->connection_error(connection, ec);
            });
          }
          else {
            connection->message->length = length;
            this->read_message_content(connection, num_additional_bytes);
          }
        }
        else
          this->connection_error(connection, ec);
      });
    }

    void read_message_content(const std::shared_ptr<Connection> &connection, std::size_t num_additional_bytes) {
      if(connection->message->length + (connection->fragmented_message ? connection->fragmented_message->length : 0) > config.max_message_size) {
        connection_error(connection, make_error_code::make_error_code(errc::message_size));
        const int status = 1009;
        const std::string reason = "message too big";
        connection->send_close(status, reason);
        connection_close(connection, status, reason);
        return;
      }
      asio::async_read(*connection->socket, connection->message->streambuf, asio::transfer_exactly(num_additional_bytes > connection->message->length ? 0 : connection->message->length - num_additional_bytes), [this, connection](const error_code &ec, std::size_t bytes_transferred) {
        auto lock = connection->handler_runner->continue_lock();
        if(!lock)
          return;
        if(!ec) {
          std::size_t num_additional_bytes = connection->message->streambuf.size() - bytes_transferred;
          std::shared_ptr<Message> next_message;
          if(num_additional_bytes > 0) { // Extract bytes that are not extra bytes in buffer (only happen when several messages are sent in handshake response)
            next_message = connection->message;
            connection->message = std::shared_ptr<Message>(new Message(next_message->fin_rsv_opcode, next_message->length));
            std::ostream ostream(&connection->message->streambuf);
            for(std::size_t c = 0; c < next_message->length; ++c)
              ostream.put(next_message->get());
          }
          else
            next_message = std::shared_ptr<Message>(new Message());

          // If connection close
          if((connection->message->fin_rsv_opcode & 0x0f) == 8) {
            connection->cancel_timeout();
            connection->set_timeout();

            int status = 0;
            if(connection->message->length >= 2) {
              unsigned char byte1 = connection->message->get();
              unsigned char byte2 = connection->message->get();
              status = (static_cast<int>(byte1) << 8) + byte2;
            }

            auto reason = connection->message->string();
            connection->send_close(status, reason);
            this->connection_close(connection, status, reason);
          }
          // If ping
          else if((connection->message->fin_rsv_opcode & 0x0f) == 9) {
            connection->cancel_timeout();
            connection->set_timeout();

            // Send pong
            auto pong_stream = std::make_shared<SendStream>();
            *pong_stream << message->string();
            connection->send(pong_stream, nullptr, fin_rsv_opcode + 1);

            if(this->on_ping)
              this->on_ping(connection);

            // Next message
            connection->message = next_message;
            this->read_message(connection, num_additional_bytes);
          }
          // If pong
          else if((connection->message->fin_rsv_opcode & 0x0f) == 10) {
            connection->cancel_timeout();
            connection->set_timeout();

            if(this->on_pong)
              this->on_pong(connection);

            // Next message
            connection->message = next_message;
            this->read_message(connection, num_additional_bytes);
          }
          // If fragmented message and not final fragment
          else if((connection->message->fin_rsv_opcode & 0x80) == 0) {
            if(!connection->fragmented_message) {
              connection->fragmented_message = connection->message;
              connection->fragmented_message->fin_rsv_opcode |= 0x80;
            }
            else {
              connection->fragmented_message->length += connection->message->length;
              std::ostream ostream(&connection->fragmented_message->streambuf);
              ostream << connection->message->rdbuf();
            }

            // Next message
            connection->message = next_message;
            this->read_message(connection, num_additional_bytes);
          }
          else {
            connection->cancel_timeout();
            connection->set_timeout();

            if(this->on_message) {
              if(connection->fragmented_message) {
                connection->fragmented_message->length += connection->message->length;
                std::ostream ostream(&connection->fragmented_message->streambuf);
                ostream << connection->message->rdbuf();

                this->on_message(connection, connection->fragmented_message);
              }
              else
                this->on_message(connection, connection->message);
            }

            // Next message
            connection->message = next_message;
            // Only reset fragmented_message for non-control frames (control frames can be in between a fragmented message)
            connection->fragmented_message = nullptr;
            this->read_message(connection, num_additional_bytes);
          }
        }
        else
          this->connection_error(connection, ec);
      });
    }

    void connection_open(const std::shared_ptr<Connection> &connection) const {
      connection->cancel_timeout();
      connection->set_timeout();

      if(on_open)
        on_open(connection);
    }

    void connection_close(const std::shared_ptr<Connection> &connection, int status, const std::string &reason) const {
      connection->cancel_timeout();
      connection->set_timeout();

      if(on_close)
        on_close(connection, status, reason);
    }

    void connection_error(const std::shared_ptr<Connection> &connection, const error_code &ec) const {
      connection->cancel_timeout();
      connection->set_timeout();

      if(on_error)
        on_error(connection, ec);
    }
  };

  template <class socket_type>
  class SocketClient : public SocketClientBase<socket_type> {};

  using WS = asio::ip::tcp::socket;

  template <>
  class SocketClient<WS> : public SocketClientBase<WS> {
  public:
    SocketClient(const std::string &server_port_path) noexcept : SocketClientBase<WS>::SocketClientBase(server_port_path, 80){};

  protected:
    void connect() override {
      std::unique_lock<std::mutex> lock(connection_mutex);
      auto connection = this->connection = std::shared_ptr<Connection>(new Connection(handler_runner, config.timeout_idle, *io_service));
      lock.unlock();
      asio::ip::tcp::resolver::query query(host, std::to_string(port));
      auto resolver = std::make_shared<asio::ip::tcp::resolver>(*io_service);
      connection->set_timeout(config.timeout_request);
      resolver->async_resolve(query, [this, connection, resolver](const error_code &ec, asio::ip::tcp::resolver::iterator it) {
        connection->cancel_timeout();
        auto lock = connection->handler_runner->continue_lock();
        if(!lock)
          return;
        if(!ec) {
          connection->set_timeout(this->config.timeout_request);
          asio::async_connect(*connection->socket, it, [this, connection, resolver](const error_code &ec, asio::ip::tcp::resolver::iterator /*it*/) {
            connection->cancel_timeout();
            auto lock = connection->handler_runner->continue_lock();
            if(!lock)
              return;
            if(!ec) {
              asio::ip::tcp::no_delay option(true);
              connection->socket->set_option(option);

              this->handshake(connection);
            }
            else
              this->connection_error(connection, ec);
          });
        }
        else
          this->connection_error(connection, ec);
      });
    }
  };
} // namespace SimpleWeb

#endif /* CLIENT_WS_HPP */
