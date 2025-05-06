#pragma once

#include <boost/asio/ssl/context.hpp>
#include <boost/beast/core.hpp>
#include <boost/asio/ssl.hpp>

#include <string_view>

namespace Json {
class Value;
}

class HttpsJsonClient
{
 public:
  HttpsJsonClient(std::string_view host, int port = 443, bool verbose = false);
  ~HttpsJsonClient();

  Json::Value get(std::string_view target, const std::vector<std::pair<std::string, std::string>>& query = {});

 private:
  void connect();

  std::string host_;
  std::string port_;

  boost::asio::io_context ioc_;
  boost::asio::ssl::context ssl_ctx_;
  boost::asio::ip::tcp::resolver resolver_;
  boost::asio::ssl::stream<boost::beast::tcp_stream> stream_;
  bool connected_ = false;

  bool m_verbose = false;
};
