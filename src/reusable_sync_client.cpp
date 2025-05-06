#include "http_sync_client/http_sync_ssl_client.hpp"

#include <json/json.h>
#include <fmt/core.h>

int main() {
  constexpr bool verbose = true;

  HttpsJsonClient client("bcl.nrel.gov", 443, verbose);
  {
    auto root = client.get("/api/metasearch/AEDG-SmOffice.json", {{"fq", "bundle:component"}, {"fq", "component_tags:Window"}});
    fmt::print("Found {} results\n", root["result_count"].asInt());
  }

  {
    auto root = client.get("/api/metasearch/AEDG-SmOffice.json", {{"fq", "bundle:component"}, {"fq", "component_tags:Door"}});
    fmt::print("Found {} results\n", root["result_count"].asInt());
  }

  {
    auto root = client.get("/api/wrong_endpoint/AEDG-SmOffice.json", {{"fq", "bundle:component"}, {"fq", "bogus:BOGUS"}});
    fmt::print("Found {} results\n", root["result_count"].asInt());
    fmt::print("{}\n", root.toStyledString());
  }
}
