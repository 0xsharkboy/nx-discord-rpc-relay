// SPDX-License-Identifier: AGPL-3.0-or-later
#include <doctest/doctest.h>

#include <algorithm>
#include <array>
#include <string>
#include <vector>

#include "crypto.hpp"

using namespace relay;

namespace {
std::array<uint8_t, 32> key_of(uint8_t fill) {
    std::array<uint8_t, 32> k{};
    k.fill(fill);
    return k;
}
}  // namespace

TEST_CASE("sha256_hex matches the known vector") {
    CHECK(sha256_hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST_CASE("random_token is 43 base64url characters and unique") {
    auto a = random_token(32);
    auto b = random_token(32);
    CHECK(a.size() == 43);
    CHECK(a != b);
    CHECK(std::all_of(a.begin(), a.end(), [](char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
               c == '_' || c == '-';
    }));
}

TEST_CASE("base64url round trip") {
    for (size_t n = 0; n < 40; ++n) {
        std::vector<uint8_t> data(n);
        for (size_t i = 0; i < n; ++i) data[i] = static_cast<uint8_t>(i * 37 + 250);
        auto enc = base64url_encode(data);
        CHECK(enc.find('=') == std::string::npos);
        auto dec = base64url_decode(enc);
        REQUIRE(dec.has_value());
        CHECK(*dec == data);
    }
}

TEST_CASE("base64url_decode rejects invalid input") {
    CHECK_FALSE(base64url_decode("a+b/").has_value());
    CHECK_FALSE(base64url_decode("abcde").has_value());
    CHECK_FALSE(base64url_decode("ab cd").has_value());
}

TEST_CASE("base64_decode handles the standard alphabet") {
    auto d = base64_decode("+/8=");
    REQUIRE(d.has_value());
    CHECK(*d == std::vector<uint8_t>{0xfb, 0xff});
    CHECK_FALSE(base64_decode("-_8=").has_value());
}

TEST_CASE("seal and open round trip") {
    auto key = key_of(7);
    auto sealed = seal(key, "secret");
    auto opened = open(key, sealed);
    REQUIRE(opened.has_value());
    CHECK(*opened == "secret");
    CHECK(sealed.size() == 12 + 6 + 16);
}

TEST_CASE("open rejects tampering, the wrong key and short input") {
    auto key = key_of(7);
    auto sealed = seal(key, "secret");
    auto tampered = sealed;
    tampered[13] ^= 1;
    CHECK_FALSE(open(key, tampered).has_value());
    CHECK_FALSE(open(key_of(8), sealed).has_value());
    CHECK_FALSE(open(key, std::vector<uint8_t>(10)).has_value());
}

TEST_CASE("seal uses a fresh nonce") {
    auto key = key_of(7);
    CHECK(seal(key, "secret") != seal(key, "secret"));
}

TEST_CASE("constant_time_equal compares content and length") {
    CHECK(constant_time_equal("abc", "abc"));
    CHECK_FALSE(constant_time_equal("abc", "abd"));
    CHECK_FALSE(constant_time_equal("abc", "abcd"));
    CHECK(constant_time_equal("", ""));
}
