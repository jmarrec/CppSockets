#ifndef BOOST_BEAST_JSONCPP_BODY
#define BOOST_BEAST_JSONCPP_BODY

#include <boost/json/stream_parser.hpp>
#include <boost/json/monotonic_resource.hpp>
#include <boost/beast/http.hpp>
#include <boost/asio/buffer.hpp>

#include <json/json.h>
#include <fmt/format.h>

struct jsoncpp_body
{
  using value_type = Json::Value;

  struct writer
  {
    using const_buffers_type = boost::asio::const_buffer;
    static constexpr std::size_t chunk_size = 32768;  // half of the probable networking buffer, let's leave some space for headers

    template <bool isRequest, class Fields>
    writer(boost::beast::http::header<isRequest, Fields> const&, value_type const& body) {
      Json::StreamWriterBuilder wbuilder;
      wbuilder["indentation"] = "  ";
      std::unique_ptr<Json::StreamWriter> const writer(wbuilder.newStreamWriter());
      writer->write(body, &ss);
    }

    void init(boost::system::error_code& ec) {
      // The serializer always works, so no error can occur here.
      ec = {};
    }

    boost::optional<std::pair<const_buffers_type, bool>> get(boost::system::error_code& ec) {
      ec = {};
      // We serialize as much as we can with the buffer. Often that'll suffice
      ss.read(buffer, sizeof(buffer));
      std::size_t bytes_read = ss.gcount();
      if (bytes_read == 0) {
        return boost::none;
      }

      return std::make_pair(boost::asio::const_buffer(buffer, bytes_read), !ss.eof());
    }

   private:
    std::stringstream ss;
    // half of the probable networking buffer, let's leave some space for headers
    char buffer[chunk_size];
  };

  struct reader
  {
    template <bool isRequest, class Fields>
    reader(boost::beast::http::header<isRequest, Fields>&, value_type& body) : body(body) {}

    void init(boost::optional<std::uint64_t> const& content_length, boost::system::error_code& ec) {
      if (content_length) {
        fmt::print("Content length={}\n", *content_length);
        ss = std::stringstream(std::string(*content_length, '\0'));
      }
      ec = {};
    }

    template <class ConstBufferSequence>
    std::size_t put(ConstBufferSequence const& buffers, boost::system::error_code& ec) {
      ec = {};
      // std::string data(boost::asio::buffers_begin(buffers), boost::asio::buffers_end(buffers));
      ss << static_cast<const char*>(buffers.data());
      return buffers.size();
    }

    void finish(boost::system::error_code& ec) {
      Json::CharReaderBuilder rbuilder;
      ec = {};
      std::string formattedErrors;
      if (!Json::parseFromStream(rbuilder, ss, &body, &formattedErrors)) {
        ec = boost::json::error::incomplete;
      }
    }

   private:
    Json::CharReaderBuilder rbuilder;
    std::stringstream ss;
    value_type& body;
  };
};

#endif
