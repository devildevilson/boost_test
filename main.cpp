#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/beast/ssl.hpp>

#include <boost/certify/extensions.hpp>
#include <boost/certify/https_verification.hpp>

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/as_tuple.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/read_until.hpp>

#include <boost/url.hpp>
#include <boost/url/src.hpp>
#include <cstdlib>
#include <iostream>
#include <string>
#include <chrono>

namespace beast = boost::beast;     // from <boost/beast.hpp>
namespace http = beast::http;       // from <boost/beast/http.hpp>
namespace net = boost::asio;        // from <boost/asio.hpp>
namespace ssl = net::ssl;           // from <boost/asio/ssl.hpp>
using tcp = net::ip::tcp;           // from <boost/asio/ip/tcp.hpp>

void print_detail() {}

template <typename Arg, typename... Args>
void print_detail(Arg&& arg, Args&&... args) {
  std::cout << " " << arg;
  print_detail(std::forward<Args>(args)...);
}

template <typename Arg, typename... Args>
void print(Arg&& arg, Args&&... args) {
  std::cout << arg;
  print_detail(std::forward<Args>(args)...);
}

template <typename... Args>
void println(Args&&... args) {
  print(std::forward<Args>(args)...);
  std::cout << "\n";
}

class time_log {
public:
  std::string str;
  std::chrono::steady_clock::time_point tp;

  time_log(std::string str) noexcept : str(std::move(str)), tp(std::chrono::steady_clock::now()) {}
  ~time_log() noexcept {
    const auto dur = std::chrono::steady_clock::now() - tp;
    const size_t mcs = std::chrono::duration_cast<std::chrono::microseconds>(dur).count();
    println(str, "took", mcs, "mcs");
  }

  time_log(const time_log &copy) noexcept = delete;
  time_log(time_log &&move) noexcept = default;
  time_log & operator=(const time_log &copy) noexcept = delete;
  time_log & operator=(time_log &&move) noexcept = default;
};

std::string_view get_url_full_path(const std::string_view &url) {
  auto final_path = url;
  const size_t found_slashes = final_path.find("//");
  if (found_slashes != std::string_view::npos) {
    final_path = final_path.substr(found_slashes+2);
  }

  const size_t first_slash = final_path.find("/");
  if (first_slash != std::string_view::npos) {
    final_path = final_path.substr(first_slash);
  } else {
    final_path = "/";
  }

  return final_path;
}

void get(const std::string_view &url, http::response<http::dynamic_body> &res, beast::flat_buffer &buffer) {
  boost::url_view u(url);
  const auto fullpath = get_url_full_path(url);

  const size_t path_slash_pos = u.path().find("/");
  const auto host_from_path = u.path().substr(0, path_slash_pos);
  const auto host = !u.scheme().empty() ? u.host() : host_from_path;
  if (host.empty()) throw std::runtime_error("Could not get host from url " + std::string(url));

  if (u.scheme().empty() || u.scheme() == "https") {
    const auto port = !u.port().empty() ? u.port() : "443";
    println(host, port);

    net::io_context ioc;
    ssl::context ctx(ssl::context::tlsv12_client);

    ctx.set_verify_mode(ssl::context::verify_peer | ssl::context::verify_fail_if_no_peer_cert);
    ctx.set_default_verify_paths();
    boost::certify::enable_native_https_server_verification(ctx);

    beast::ssl_stream<beast::tcp_stream> stream(ioc, ctx);
    //boost::certify::set_server_hostname(beast::get_lowest_layer(stream), host);
    //boost::certify::sni_hostname(beast::get_lowest_layer(stream), host);

    const auto host_str = std::string(host);
    if (!SSL_set_tlsext_host_name(stream.native_handle(), host_str.c_str())) {
      beast::error_code ec{static_cast<int>(::ERR_get_error()), net::error::get_ssl_category()};
      throw beast::system_error{ec};
    }

    tcp::resolver resolver(ioc);
    auto const results = resolver.resolve(host, port);
    beast::get_lowest_layer(stream).connect(results);
    stream.handshake(ssl::stream_base::client);

    http::request<http::string_body> req{http::verb::get, fullpath, 11};
    req.set(http::field::host, host);
    req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
    http::write(stream, req);

    http::read(stream, buffer, res);

    beast::error_code ec;
    stream.shutdown(ec);
    // http://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
    // https://github.com/boostorg/beast/issues/824
    if (ec == net::error::eof || ec == ssl::error::stream_truncated) ec = {};
    if (ec) throw beast::system_error{ec};
  } else {
    const auto port = !u.port().empty() ? u.port() : "80";
    println(host, port);

    net::io_context ioc; 
    tcp::resolver resolver(ioc);
    beast::tcp_stream stream(ioc);
    auto const results = resolver.resolve(host, port);
    stream.connect(results);

    http::request<http::string_body> req{http::verb::get, fullpath, 11};
    req.set(http::field::host, host);
    req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

    println(req);

    http::write(stream, req);
    http::read(stream, buffer, res);

    beast::error_code ec;
    stream.socket().shutdown(tcp::socket::shutdown_both, ec);

    if(ec && ec != beast::errc::not_connected) throw beast::system_error{ec};
  }
}

net::awaitable<std::tuple<http::response<http::dynamic_body>, beast::flat_buffer>>
//net::awaitable<void> 
get(const std::string_view &url) {
  boost::url_view u(url);
  const auto fullpath = get_url_full_path(url);

  const size_t path_slash_pos = u.path().find("/");
  const auto host_from_path = u.path().substr(0, path_slash_pos);
  const auto host = !u.scheme().empty() ? u.host() : host_from_path;
  const bool is_https = u.scheme().empty() || u.scheme() == "https";
  const auto port = !u.port().empty() ? u.port() : (is_https ? "443" : "80");
  //println(host, port);
  if (host.empty()) throw std::runtime_error("Could not get host from url " + std::string(url));

  const auto &ioc = co_await net::this_coro::executor;
  tcp::resolver resolver(ioc);
  auto const results = co_await resolver.async_resolve(host, port, net::use_awaitable);

  beast::flat_buffer buffer;
  http::response<http::dynamic_body> res;

  if (is_https) {
    ssl::context ctx(ssl::context::tlsv12_client);
    ctx.set_verify_mode(ssl::context::verify_peer | ssl::context::verify_fail_if_no_peer_cert);
    ctx.set_default_verify_paths();
    boost::certify::enable_native_https_server_verification(ctx);

    beast::ssl_stream<beast::tcp_stream> stream(ioc, ctx);
    //boost::certify::set_server_hostname(beast::get_lowest_layer(stream), host);
    //boost::certify::sni_hostname(beast::get_lowest_layer(stream), host);

    const auto host_str = std::string(host);
    if (!SSL_set_tlsext_host_name(stream.native_handle(), host_str.c_str())) {
      beast::error_code ec{static_cast<int>(::ERR_get_error()), net::error::get_ssl_category()};
      throw beast::system_error{ec};
    }

    auto ep = co_await beast::get_lowest_layer(stream).async_connect(results, net::use_awaitable);
    co_await stream.async_handshake(ssl::stream_base::client, net::use_awaitable);

    http::request<http::string_body> req{http::verb::get, fullpath, 11};
    req.set(http::field::host, host);
    req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
    co_await http::async_write(stream, req, net::use_awaitable);

    co_await http::async_read(stream, buffer, res, net::use_awaitable);

    //println(res);

    beast::error_code ec;
    stream.shutdown(ec);
    // http://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
    // https://github.com/boostorg/beast/issues/824
    if (ec == net::error::eof || ec == ssl::error::stream_truncated) ec = {};
    if (ec) throw beast::system_error{ec};
  } else {
    beast::tcp_stream stream(ioc);
    auto ep = co_await stream.async_connect(results, net::use_awaitable);

    http::request<http::string_body> req{http::verb::get, fullpath, 11};
    req.set(http::field::host, host);
    req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
    co_await http::async_write(stream, req, net::use_awaitable);

    co_await http::async_read(stream, buffer, res, net::use_awaitable);

    beast::error_code ec;
    stream.socket().shutdown(tcp::socket::shutdown_both, ec);

    if(ec && ec != beast::errc::not_connected) throw beast::system_error{ec};
  }

  co_return std::make_tuple(std::move(res), std::move(buffer));
}

net::awaitable<std::tuple<http::response<http::dynamic_body>, beast::flat_buffer>>
//net::awaitable<void> 
post(const std::string_view url, const std::string_view type, std::string content) {
  boost::url_view u(url);
  const auto fullpath = get_url_full_path(url);

  const size_t path_slash_pos = u.path().find("/");
  const auto host_from_path = u.path().substr(0, path_slash_pos);
  const auto host = !u.scheme().empty() ? u.host() : host_from_path;
  const bool is_https = u.scheme().empty() || u.scheme() == "https";
  const auto port = !u.port().empty() ? u.port() : (is_https ? "443" : "80");
  //println(host, port);
  if (host.empty()) throw std::runtime_error("Could not get host from url " + std::string(url));

  const auto &ioc = co_await net::this_coro::executor;
  tcp::resolver resolver(ioc);
  auto const results = co_await resolver.async_resolve(host, port, net::use_awaitable);

  beast::flat_buffer buffer;
  http::response<http::dynamic_body> res;

  if (is_https) {
    ssl::context ctx(ssl::context::tlsv12_client);
    ctx.set_verify_mode(ssl::context::verify_peer | ssl::context::verify_fail_if_no_peer_cert);
    ctx.set_default_verify_paths();
    boost::certify::enable_native_https_server_verification(ctx);

    beast::ssl_stream<beast::tcp_stream> stream(ioc, ctx);
    //boost::certify::set_server_hostname(beast::get_lowest_layer(stream), host);
    //boost::certify::sni_hostname(beast::get_lowest_layer(stream), host);

    const auto host_str = std::string(host);
    if (!SSL_set_tlsext_host_name(stream.native_handle(), host_str.c_str())) {
      beast::error_code ec{static_cast<int>(::ERR_get_error()), net::error::get_ssl_category()};
      throw beast::system_error{ec};
    }

    auto ep = co_await beast::get_lowest_layer(stream).async_connect(results, net::use_awaitable);
    co_await stream.async_handshake(ssl::stream_base::client, net::use_awaitable);

    http::request<http::string_body> req{http::verb::post, fullpath, 11};
    req.set(http::field::host, host);
    req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
    req.set(http::field::content_type, type);
    req.set(http::field::content_length, std::to_string(content.size()));
    req.body() = std::move(content);
    co_await http::async_write(stream, req, net::use_awaitable);

    co_await http::async_read(stream, buffer, res, net::use_awaitable);

    //println(res);

    beast::error_code ec;
    stream.shutdown(ec);
    // http://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
    // https://github.com/boostorg/beast/issues/824
    if (ec == net::error::eof || ec == ssl::error::stream_truncated) ec = {};
    if (ec) throw beast::system_error{ec};
  } else {
    beast::tcp_stream stream(ioc);
    auto ep = co_await stream.async_connect(results, net::use_awaitable);

    http::request<http::string_body> req{http::verb::post, fullpath, 11};
    req.set(http::field::host, host);
    req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
    req.set(http::field::content_type, type);
    req.set(http::field::content_length, std::to_string(content.size()));
    req.body() = std::move(content);
    co_await http::async_write(stream, req, net::use_awaitable);

    co_await http::async_read(stream, buffer, res, net::use_awaitable);

    beast::error_code ec;
    stream.socket().shutdown(tcp::socket::shutdown_both, ec);

    if(ec && ec != beast::errc::not_connected) throw beast::system_error{ec};
  }

  co_return std::make_tuple(std::move(res), std::move(buffer));
}

net::awaitable<void> server(const uint32_t port) {
  const auto &ioc = co_await net::this_coro::executor;
  tcp::acceptor acceptor(ioc, tcp::endpoint(tcp::v4(), port));

  while (true) {
    boost::system::error_code ec;
    auto socket = co_await acceptor.async_accept(net::use_awaitable);

    //net::streambuf request;
    //const size_t bytes_readed = co_await net::async_read_until(socket, request, "\r\n\r\n", net::use_awaitable);
    beast::flat_buffer buffer;
    http::request<http::dynamic_body> request;
    co_await http::async_read(socket, buffer, request, net::use_awaitable);

    // надо ли как нибудь реагировать? или можно сразу отправить тип получили
    const std::string_view resp = "HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nReceived";
    //http::response<http::string_body> resp;
    const size_t bytes_transferred = co_await net::async_write(socket, net::buffer(resp), net::use_awaitable);
    socket.shutdown(tcp::socket::shutdown_send, ec);

    if (ec) throw beast::system_error{ec};

    //std::string request_str((std::istreambuf_iterator<char>(&request)), std::istreambuf_iterator<char>());

    // теперь нам бы эту строку распарсить, телеграм бот чисто шлет json, его бы надо быстро превращать в структуры
    println(request);
  }
}

int main(int argc, char** argv) {
  if (argc < 2) {
    std::cerr <<
      "Usage: " << argv[0] << " <url>\n" <<
      "Example:\n" <<
      "    " << argv[0] << " www.example.com\n" <<
      "    " << argv[0] << " https://sites.google.com\n";
    return EXIT_FAILURE;
  }

  const std::string_view host = argv[1];

  net::io_context ioc;
  //net::signal_set signals(ioc, SIGINT, SIGTERM);
  //net::co_spawn(ioc, get(host), net::detached);
  //auto fut = net::co_spawn(ioc, get(host), net::use_future);
  const std::string_view type = "text/plain";
  auto fut = net::co_spawn(ioc, post(host, type, "Hello world"), net::use_future);

  net::co_spawn(ioc, server(5050), net::detached);
  {
    //time_log log("ioc.run()");
    ioc.run();
  }

  {
    time_log log("fut.get()");
    const auto [ res, buffer ] = fut.get();
    println(res);
  }


  return EXIT_SUCCESS;
}

