#include "http_sync_ssl_client.hpp"

#include "../jsoncpp_body.hpp"

#include <boost/asio/ssl/verify_mode.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/url.hpp>
#include <cstdlib>
#include <iostream>

#include <json/json.h>
#include <fmt/format.h>
#include <fmt/ostream.h>
#include <fmt/color.h>

namespace beast = boost::beast;  // from <boost/beast.hpp>
namespace http = beast::http;    // from <boost/beast/http.hpp>
namespace net = boost::asio;     // from <boost/asio.hpp>
namespace ssl = net::ssl;        // from <boost/asio/ssl.hpp>
using tcp = net::ip::tcp;        // from <boost/asio/ip/tcp.hpp>

template <>
struct fmt::formatter<boost::urls::url>
{
  constexpr auto parse(format_parse_context& ctx) {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(const boost::urls::url& u, FormatContext& ctx) const {
    return fmt::format_to(ctx.out(),
                          "url       : {}\n"
                          "scheme    : {}\n"
                          "authority : {}\n"
                          "userinfo  : {}\n"
                          "user      : {}\n"
                          "password  : {}\n"
                          "host      : {}\n"
                          "port      : {}\n"
                          "path      : {}\n"
                          "query     : {}\n"
                          "fragment  : {}\n"
                          "target    : {}\n",
                          u.buffer(), u.scheme(), u.encoded_authority(), u.encoded_userinfo(), u.encoded_user(), u.encoded_password(),
                          u.encoded_host(), u.port(), u.encoded_path(), u.encoded_query(), u.encoded_fragment(), u.encoded_target());
  }
};

void load_root_certificates(ssl::context& ctx) {

  std::string cert = "# DigiCert Global Root G2\n"
                     "-----BEGIN CERTIFICATE-----\n"
                     "MIIDjjCCAnagAwIBAgIQAzrx5qcRqaC7KGSxHQn65TANBgkqhkiG9w0BAQsFADBh\n"
                     "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\n"
                     "d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBH\n"
                     "MjAeFw0xMzA4MDExMjAwMDBaFw0zODAxMTUxMjAwMDBaMGExCzAJBgNVBAYTAlVT\n"
                     "MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j\n"
                     "b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IEcyMIIBIjANBgkqhkiG\n"
                     "9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuzfNNNx7a8myaJCtSnX/RrohCgiN9RlUyfuI\n"
                     "2/Ou8jqJkTx65qsGGmvPrC3oXgkkRLpimn7Wo6h+4FR1IAWsULecYxpsMNzaHxmx\n"
                     "1x7e/dfgy5SDN67sH0NO3Xss0r0upS/kqbitOtSZpLYl6ZtrAGCSYP9PIUkY92eQ\n"
                     "q2EGnI/yuum06ZIya7XzV+hdG82MHauVBJVJ8zUtluNJbd134/tJS7SsVQepj5Wz\n"
                     "tCO7TG1F8PapspUwtP1MVYwnSlcUfIKdzXOS0xZKBgyMUNGPHgm+F6HmIcr9g+UQ\n"
                     "vIOlCsRnKPZzFBQ9RnbDhxSJITRNrw9FDKZJobq7nMWxM4MphQIDAQABo0IwQDAP\n"
                     "BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUTiJUIBiV\n"
                     "5uNu5g/6+rkS7QYXjzkwDQYJKoZIhvcNAQELBQADggEBAGBnKJRvDkhj6zHd6mcY\n"
                     "1Yl9PMWLSn/pvtsrF9+wX3N3KjITOYFnQoQj8kVnNeyIv/iPsGEMNKSuIEyExtv4\n"
                     "NeF22d+mQrvHRAiGfzZ0JFrabA0UWTW98kndth/Jsw1HKj2ZL7tcu7XUIOGZX1NG\n"
                     "Fdtom/DzMNU+MeKNhJ7jitralj41E6Vf8PlwUHBHQRFXGU7Aj64GxJUTFy8bJZ91\n"
                     "8rGOmaFvE7FBcf6IKshPECBV1/MUReXgRPTqh5Uykw7+U0b6LJ3/iyK5S9kJRaTe\n"
                     "pLiaWN0bfVKfjllDiIGknibVb63dDcY3fe0Dkhvld1927jyNxF1WW6LZZm6zNTfl\n"
                     "MrY=\n"
                     "-----END CERTIFICATE-----\n"
                     "\n";
  boost::system::error_code ec;
  ctx.add_certificate_authority(boost::asio::buffer(cert.data(), cert.size()), ec);
  if (ec) {
    throw std::runtime_error(fmt::format("Failed to load root certificate: {}", ec.message()));
    return;
  }
}

HttpsJsonClient::HttpsJsonClient(std::string_view host, int port, bool verbose)
  : host_(host), port_(std::to_string(port)), ssl_ctx_(ssl::context::tlsv12_client), resolver_(ioc_), stream_(ioc_, ssl_ctx_), m_verbose(verbose) {
  ssl_ctx_.set_verify_mode(ssl::verify_peer);
  load_root_certificates(ssl_ctx_);  // your existing function

  connect();
}

void HttpsJsonClient::connect() {
  if (!SSL_set_tlsext_host_name(stream_.native_handle(), host_.c_str())) {
    throw beast::system_error(static_cast<int>(::ERR_get_error()), net::error::get_ssl_category());
  }

  stream_.set_verify_callback(ssl::host_name_verification(host_));

  auto const results = resolver_.resolve(host_, port_);
  beast::get_lowest_layer(stream_).connect(results);
  stream_.handshake(ssl::stream_base::client);
  connected_ = true;
}

Json::Value HttpsJsonClient::get(std::string_view target, const std::vector<std::pair<std::string, std::string>>& query) {
  if (!connected_) {
    throw std::runtime_error("Not connected");
  }

  boost::urls::url url;
  url.set_scheme("https");
  url.set_host(host_);
  url.set_port(port_);
  url.set_path(target);

  for (const auto& [key, val] : query) {
    url.params().append(boost::urls::param_view{key, val});
  }

  if (m_verbose) {
    fmt::print(fmt::fg(fmt::color::orange),
               "┌{0:─^{2}}┐\n"
               "│{1: ^{2}}│\n"
               "└{0:─^{2}}┘",
               "", "Performing a GET on url", 80);
    fmt::print("\n{}\n", url);
  }

  http::request<http::string_body> req{http::verb::get, url.encoded_target(), 11};
  req.set(http::field::host, host_);
  req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

  http::write(stream_, req);

  beast::flat_buffer buffer;
  http::response<jsoncpp_body> res;
  http::read(stream_, buffer, res);

  if (res.result() != http::status::ok) {
    throw std::runtime_error(fmt::format("HTTP error: {}", res.result_int()));
  }

  return res.body();
}

HttpsJsonClient::~HttpsJsonClient() {
  beast::error_code ec;
  stream_.shutdown(ec);
  if (ec != net::ssl::error::stream_truncated && ec) {
    std::cerr << "Shutdown error: " << ec.message() << "\n";
  }
}
