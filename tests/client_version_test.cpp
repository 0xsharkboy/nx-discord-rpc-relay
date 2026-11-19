// SPDX-License-Identifier: AGPL-3.0-or-later
#include <doctest/doctest.h>

#include <string>

#include "client_version.hpp"

using namespace relay;

TEST_CASE("client_version: version_compare_numeric") {
    const Version v0_9_1{0, 9, 1}, v0_10_0{0, 10, 0}, v0_6_0{0, 6, 0}, v1_0_0{1, 0, 0};
    CHECK(older(v0_9_1, v0_10_0));
    CHECK_FALSE(older(v0_10_0, v0_9_1));
    CHECK(older(v0_6_0, v1_0_0));
    CHECK(older(Version{0, 5, 9}, v0_6_0));
    CHECK(older(Version{0, 6, 0}, Version{0, 6, 1}));
    CHECK_FALSE(older(v0_6_0, v0_6_0));
    CHECK(to_string(v0_10_0) == "0.10.0");
}

TEST_CASE("client_version: parse_version accepts X.Y.Z only") {
    CHECK(parse_version("0.6.0") == Version{0, 6, 0});
    CHECK(parse_version("10.20.30") == Version{10, 20, 30});
    for (auto bad : {"", "0.5", "0.5.0.1", "0.5.0-beta", "v0.5.0", "0..0", ".1.2", "1.2.", "a.b.c", " 0.5.0",
                     "0.5.0 ", "+1.2.3", "-1.2.3", "99999999999.0.0"})
        CHECK_FALSE_MESSAGE(parse_version(bad).has_value(), bad);
}

TEST_CASE("client_version: parse_client_user_agent") {
    CHECK(parse_client_user_agent("nx-discord-rpc/0.6.0") == Version{0, 6, 0});
    CHECK(parse_client_user_agent("nx-discord-rpc/0.10.2") == Version{0, 10, 2});
    for (auto other : {"", "cpp-httplib/0.18.7", "curl/8.0", "nx-discord-rpc/", "nx-discord-rpc/0.5",
                       "nx-discord-rpc/0.5.0.1", "nx-discord-rpc/0.5.0-beta", "nx-discord-rpc/0.5.0 extra",
                       "NX-DISCORD-RPC/0.5.0", "my-nx-discord-rpc/0.5.0", "nx-discord-rpc/99999999999.0.0"})
        CHECK_FALSE_MESSAGE(parse_client_user_agent(other).has_value(), other);
}

TEST_CASE("client_version: version_counts_distinct_keys_and_drain") {
    VersionCounts counts;
    CHECK(counts.drain_line() == "relay: client versions in the last 24 h: none");

    counts.seen(Version{0, 6, 0}, "a");
    counts.seen(Version{0, 6, 0}, "a");
    counts.seen(Version{0, 6, 0}, "b");
    counts.seen(Version{0, 5, 0}, "c");
    counts.seen(Version{0, 10, 0}, "d");
    counts.seen(Version{0, 9, 1}, "d");  // updated during the day: counted under both
    counts.seen_other("e");
    counts.seen_other("e");
    counts.seen_other("f");
    CHECK(counts.drain_line() == "relay: client versions in the last 24 h: 0.10.0=1 0.9.1=1 0.6.0=2 0.5.0=1 other=2");
    // Drained: a new window starts empty.
    CHECK(counts.drain_line() == "relay: client versions in the last 24 h: none");

    counts.seen_other("x");
    CHECK(counts.drain_line() == "relay: client versions in the last 24 h: other=1");
}

TEST_CASE("client_version: distinct versions are capped, the rest counts as other") {
    VersionCounts counts;
    for (uint32_t i = 0; i < VersionCounts::kMaxVersions + 5; ++i) counts.seen(Version{0, 0, i}, "k" + std::to_string(i));
    counts.seen(Version{0, 0, 0}, "again");  // an existing bucket still counts
    const auto line = counts.drain_line();
    CHECK(line.find("other=5") != std::string::npos);
    CHECK(line.find(" 0.0.0=2") != std::string::npos);
    CHECK(line.find("0.0." + std::to_string(VersionCounts::kMaxVersions) + "=") == std::string::npos);
}
