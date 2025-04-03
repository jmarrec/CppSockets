// https://github.com/boostorg/beast/blob/1d8dfae490125bd63efedfa7a3ecf20e8e9b54a5/example/http/client/sync-ssl/http_client_sync_ssl.cpp

//
// Copyright (c) 2016-2019 Vinnie Falco (vinnie dot falco at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/boostorg/beast
//

//------------------------------------------------------------------------------
//
// Example: HTTP SSL client, synchronous
//
//------------------------------------------------------------------------------

// #include "example/common/root_certificates.hpp"
#include "jsoncpp_body.hpp"

#include <boost/asio/ssl/verify_mode.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <cstdlib>
#include <iostream>

#include <json/json.h>
#include <fmt/format.h>
#include <fmt/ostream.h>

namespace beast = boost::beast;  // from <boost/beast.hpp>
namespace http = beast::http;    // from <boost/beast/http.hpp>
namespace net = boost::asio;     // from <boost/asio.hpp>
namespace ssl = net::ssl;        // from <boost/asio/ssl.hpp>
using tcp = net::ip::tcp;        // from <boost/asio/ip/tcp.hpp>

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
    return;
  }
}

// Performs an HTTP GET and prints the response
int main(int argc, char** argv) {
  try {
    // Check command line arguments.
    if (argc != 4 && argc != 5) {
      std::cerr << "Usage: http-client-sync-ssl <host> <port> <target> [<HTTP version: 1.0 or 1.1(default)>]\n"
                << "Example:\n"
                << "    http-client-sync-ssl www.example.com 443 /\n"
                << "    http-client-sync-ssl www.example.com 443 / 1.0\n";
      return EXIT_FAILURE;
    }
    auto const host = argv[1];
    auto const port = argv[2];
    auto const target = argv[3];
    int version = argc == 5 && !std::strcmp("1.0", argv[4]) ? 10 : 11;

    // The io_context is required for all I/O
    net::io_context ioc;

    // The SSL context is required, and holds certificates
    ssl::context ctx(ssl::context::tlsv12_client);

    // This holds the root certificate used for verification
    // load_root_certificates(ctx);

    // Verify the remote server's certificate
    ctx.set_verify_mode(ssl::verify_none);  //verify_peer, verify_none

    // These objects perform our I/O
    tcp::resolver resolver(ioc);
    ssl::stream<beast::tcp_stream> stream(ioc, ctx);

    // Set SNI Hostname (many hosts need this to handshake successfully)
    if (!SSL_set_tlsext_host_name(stream.native_handle(), host)) {
      throw beast::system_error(static_cast<int>(::ERR_get_error()), net::error::get_ssl_category());
    }

    // Set the expected hostname in the peer certificate for verification
    stream.set_verify_callback(ssl::host_name_verification(host));

    // Look up the domain name
    auto const results = resolver.resolve(host, port);

    // Make the connection on the IP address we get from a lookup
    beast::get_lowest_layer(stream).connect(results);

    // Perform the SSL handshake
    stream.handshake(ssl::stream_base::client);

    // Set up an HTTP GET request message
    http::request<http::string_body> req{http::verb::get, target, version};
    req.set(http::field::host, host);
    req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

    // Send the HTTP request to the remote host
    http::write(stream, req);

    // This buffer is used for reading and must be persisted
    beast::flat_buffer buffer;

#if 0
    // Declare a container to hold the response
    http::response<http::dynamic_body> res;

    // Receive the HTTP response
    http::read(stream, buffer, res);

    fmt::print("Status: int={}\n", res.result_int());
    std::cout << res.result() << std::endl;
    if (res.result() == http::status::ok) {
      fmt::print("Reading JSON\n");
      Json::CharReaderBuilder rbuilder;
      std::stringstream ss;
      ss << boost::beast::buffers_to_string(res.body().data());
      fmt::print("\n\n\n{}\n\n", ss.str());
      std::string formattedErrors;
      Json::Value root;
      bool parsingSuccessful = Json::parseFromStream(rbuilder, ss, &root, &formattedErrors);
      if (parsingSuccessful) {
        Json::StreamWriterBuilder wbuilder;
        // mimic the old StyledWriter behavior:
        wbuilder["indentation"] = "  ";
        std::string result = Json::writeString(wbuilder, root);
        fmt::print("{}\n", result);
      }
    }
#else
    http::response<jsoncpp_body> res;

    // Receive the HTTP response
    http::read(stream, buffer, res);

    // Write the message to standard out
    // std::cout << res << std::endl;
    if (res.result() == http::status::ok) {
      Json::Value& root = res.body();
      fmt::print("Found {} results\n", root["total_results"].asInt());
    }

#endif
    // Write the message to standard out
    // std::cout << res << std::endl;

    // Gracefully close the stream
    beast::error_code ec;
    stream.shutdown(ec);

    // ssl::error::stream_truncated, also known as an SSL "short read",
    // indicates the peer closed the connection without performing the
    // required closing handshake (for example, Google does this to
    // improve performance). Generally this can be a security issue,
    // but if your communication protocol is self-terminated (as
    // it is with both HTTP and WebSocket) then you may simply
    // ignore the lack of close_notify.
    //
    // https://github.com/boostorg/beast/issues/38
    //
    // https://security.stackexchange.com/questions/91435/how-to-handle-a-malicious-ssl-tls-shutdown
    //
    // When a short read would cut off the end of an HTTP message,
    // Beast returns the error beast::http::error::partial_message.
    // Therefore, if we see a short read here, it has occurred
    // after the message has been completed, so it is safe to ignore it.

    if (ec != net::ssl::error::stream_truncated) {
      throw beast::system_error{ec};
    }
  } catch (std::exception const& e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
