#include "lite.h"

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
#include <boost/asio/use_future.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/read_until.hpp>

#include <boost/url.hpp>
#include <cstdlib>

#include <boost/url/src.hpp>

namespace liteh {
  namespace ssl = net::ssl;           // from <boost/asio/ssl.hpp>
  using tcp = net::ip::tcp;           // from <boost/asio/ip/tcp.hpp>

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

  net::awaitable<std::tuple<http::response<http::dynamic_body>, beast::flat_buffer>>
  get(const std::string_view url) {
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
}