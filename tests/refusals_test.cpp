// SPDX-License-Identifier: AGPL-3.0-or-later
#include <doctest/doctest.h>

#include <string>

#include "refusals.hpp"

using namespace relay;

TEST_CASE("refusals: the daily line counts per code, most frequent first, then clears") {
    RefusalCounts c;
    CHECK(c.drain_line() == "relay: refused requests in the last 24 h: none");
    c.refused("invalid_body");
    c.refused("unauthorized");
    c.refused("client_outdated");
    c.refused("unauthorized");
    c.refused("client_outdated");
    c.refused("client_outdated");
    CHECK(c.drain_line() ==
          "relay: refused requests in the last 24 h: client_outdated=3 unauthorized=2 invalid_body=1");
    CHECK(c.drain_line() == "relay: refused requests in the last 24 h: none");
}

TEST_CASE("refusals: codes past the cap count as other") {
    RefusalCounts c;
    for (size_t i = 0; i < RefusalCounts::kMaxCodes; ++i) c.refused("code" + std::to_string(i));
    c.refused("one_too_many");
    c.refused("another");
    c.refused("code0");
    const auto line = c.drain_line();
    CHECK(line.find("code0=2") != std::string::npos);
    CHECK(line.find("one_too_many") == std::string::npos);
    CHECK(line.ends_with(" other=2"));
}
