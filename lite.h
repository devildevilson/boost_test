#ifndef LITEH_H
#define LITEH_H

#include <string>
#include <string_view>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>

namespace liteh {
  namespace beast = boost::beast;     // from <boost/beast.hpp>
  namespace http = beast::http;       // from <boost/beast/http.hpp>
  namespace net = boost::asio;        // from <boost/asio.hpp>

  net::awaitable<std::tuple<http::response<http::dynamic_body>, beast::flat_buffer>>
    get(const std::string_view url);

  net::awaitable<std::tuple<http::response<http::dynamic_body>, beast::flat_buffer>> 
    post(const std::string_view url, const std::string_view type, std::string content);
}

#endif