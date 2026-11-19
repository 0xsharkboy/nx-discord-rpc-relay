// SPDX-License-Identifier: AGPL-3.0-or-later
#include <doctest/doctest.h>

#include <map>
#include <string>
#include <vector>

#include "config.hpp"
#include "crypto.hpp"

using namespace relay;

namespace {
using Env = std::map<std::string, std::string>;

std::variant<Config, std::string> load(const Env& env) {
    return load_config([&](const char* name) -> std::optional<std::string> {
        auto it = env.find(name);
        if (it == env.end()) return std::nullopt;
        return it->second;
    });
}

std::string key_b64() {
    std::vector<uint8_t> raw(32, 0x42);
    std::string s = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=";
    REQUIRE(base64_decode(s).value() == raw);
    return s;
}

Env full() {
    return {{"DISCORD_CLIENT_ID", "1234567890123456789"},
            {"DISCORD_CLIENT_SECRET", "s3cr3t-client-value"},
            {"TOKEN_ENC_KEY", key_b64()},
            {"PUBLIC_BASE_URL", "https://rpc.example.dev"}};
}

std::string error_of(const Env& env) {
    auto r = load(env);
    REQUIRE(std::holds_alternative<std::string>(r));
    return std::get<std::string>(r);
}

bool has(const std::string& s, const std::string& needle) { return s.find(needle) != std::string::npos; }
}  // namespace

TEST_CASE("load_config names every missing required variable") {
    auto e = error_of({});
    CHECK(has(e, "DISCORD_CLIENT_ID"));
    CHECK(has(e, "DISCORD_CLIENT_SECRET"));
    CHECK(has(e, "TOKEN_ENC_KEY"));
    CHECK(has(e, "PUBLIC_BASE_URL"));
    auto env = full();
    env.erase("TOKEN_ENC_KEY");
    e = error_of(env);
    CHECK(has(e, "TOKEN_ENC_KEY"));
    CHECK_FALSE(has(e, "DISCORD_CLIENT_ID"));
}

TEST_CASE("load_config applies defaults") {
    auto r = load(full());
    REQUIRE(std::holds_alternative<Config>(r));
    auto& c = std::get<Config>(r);
    CHECK(c.client_id == "1234567890123456789");
    CHECK(c.client_secret == "s3cr3t-client-value");
    CHECK(c.public_base_url == "https://rpc.example.dev");
    CHECK(c.listen_host == "0.0.0.0");
    CHECK(c.listen_port == 8080);
    CHECK(c.data_dir == "/data");
    CHECK_FALSE(c.trust_proxy);
    CHECK_FALSE(c.admin_key.has_value());
    CHECK(c.token_key[0] == 0x42);
    CHECK(c.token_key[31] == 0x42);
}

TEST_CASE("load_config reads overrides") {
    auto env = full();
    env["LISTEN_ADDR"] = "127.0.0.1:9000";
    env["DATA_DIR"] = "/tmp/x";
    env["TRUST_PROXY"] = "true";
    env["ADMIN_KEY"] = "adm";
    auto r = load(env);
    REQUIRE(std::holds_alternative<Config>(r));
    auto& c = std::get<Config>(r);
    CHECK(c.listen_host == "127.0.0.1");
    CHECK(c.listen_port == 9000);
    CHECK(c.data_dir == "/tmp/x");
    CHECK(c.trust_proxy);
    CHECK(c.admin_key == "adm");
}

TEST_CASE("load_config treats an empty ADMIN_KEY as unset") {
    auto env = full();
    env["ADMIN_KEY"] = "";
    auto r = load(env);
    REQUIRE(std::holds_alternative<Config>(r));
    CHECK_FALSE(std::get<Config>(r).admin_key.has_value());
}

TEST_CASE("load_config accepts TRUST_PROXY spellings") {
    for (auto [v, expected] : {std::pair{"true", true}, {"1", true}, {"false", false}, {"0", false}}) {
        auto env = full();
        env["TRUST_PROXY"] = v;
        auto r = load(env);
        REQUIRE(std::holds_alternative<Config>(r));
        CHECK(std::get<Config>(r).trust_proxy == expected);
    }
    auto env = full();
    env["TRUST_PROXY"] = "yes";
    CHECK(has(error_of(env), "TRUST_PROXY"));
}

TEST_CASE("load_config rejects a bad TOKEN_ENC_KEY") {
    auto env = full();
    env["TOKEN_ENC_KEY"] = "c2hvcnQ=";
    auto e = error_of(env);
    CHECK(has(e, "TOKEN_ENC_KEY"));
    CHECK_FALSE(has(e, "c2hvcnQ="));
    env["TOKEN_ENC_KEY"] = "!!!not base64!!!";
    CHECK(has(error_of(env), "TOKEN_ENC_KEY"));
}

TEST_CASE("load_config rejects a bad PUBLIC_BASE_URL") {
    auto env = full();
    env["PUBLIC_BASE_URL"] = "https://rpc.example.dev/";
    CHECK(has(error_of(env), "PUBLIC_BASE_URL"));
    env["PUBLIC_BASE_URL"] = "http://rpc.example.dev";
    CHECK(has(error_of(env), "PUBLIC_BASE_URL"));
    env["PUBLIC_BASE_URL"] = "https://";
    CHECK(has(error_of(env), "PUBLIC_BASE_URL"));
}

TEST_CASE("load_config rejects a bad LISTEN_ADDR") {
    for (auto v : {"8080", "host:", ":8080", "host:abc", "host:0", "host:65536", "host:-1", "host:80x"}) {
        auto env = full();
        env["LISTEN_ADDR"] = v;
        CHECK_MESSAGE(has(error_of(env), "LISTEN_ADDR"), v);
    }
    auto env = full();
    env["LISTEN_ADDR"] = "h:65535";
    CHECK(std::holds_alternative<Config>(load(env)));
    env["LISTEN_ADDR"] = "h:1";
    CHECK(std::holds_alternative<Config>(load(env)));
}

TEST_CASE("load_config: publish_threshold_is_ignored") {
    for (auto v : {"2", "x", "0", ""}) {
        auto env = full();
        env["PUBLISH_THRESHOLD"] = v;
        CHECK_MESSAGE(std::holds_alternative<Config>(load(env)), v);
    }
}

TEST_CASE("load_config rejects a non-numeric DISCORD_CLIENT_ID") {
    auto env = full();
    env["DISCORD_CLIENT_ID"] = "12ab";
    CHECK(has(error_of(env), "DISCORD_CLIENT_ID"));
}

TEST_CASE("load_config errors never contain secret values") {
    auto env = full();
    env["ADMIN_KEY"] = "super-admin-secret";
    env["PUBLIC_BASE_URL"] = "http://bad";
    auto e = error_of(env);
    CHECK_FALSE(has(e, "s3cr3t-client-value"));
    CHECK_FALSE(has(e, "super-admin-secret"));
    CHECK_FALSE(has(e, key_b64()));
}

TEST_CASE("load_config: min_client_version is unset by default or when empty") {
    auto r = load(full());
    REQUIRE(std::holds_alternative<Config>(r));
    CHECK_FALSE(std::get<Config>(r).min_client_version.has_value());
    auto env = full();
    env["MIN_CLIENT_VERSION"] = "";
    r = load(env);
    REQUIRE(std::holds_alternative<Config>(r));
    CHECK_FALSE(std::get<Config>(r).min_client_version.has_value());
}

TEST_CASE("load_config reads MIN_CLIENT_VERSION") {
    auto env = full();
    env["MIN_CLIENT_VERSION"] = "0.10.2";
    auto r = load(env);
    REQUIRE(std::holds_alternative<Config>(r));
    CHECK(std::get<Config>(r).min_client_version == Version{0, 10, 2});
}

TEST_CASE("load_config: invalid_min_version_is_config_error") {
    for (auto v : {"0.6", "v0.6.0", "0.6.0-beta", "0.6.0.1", "latest", " 0.6.0", "99999999999.0.0"}) {
        auto env = full();
        env["MIN_CLIENT_VERSION"] = v;
        auto e = error_of(env);
        CHECK_MESSAGE(has(e, "MIN_CLIENT_VERSION"), v);
        CHECK_FALSE_MESSAGE(has(e, v), v);
    }
}

TEST_CASE("load_config: BADGE_URL defaults to the project page and accepts an https override") {
    auto env = full();
    auto r = load(env);
    REQUIRE(std::holds_alternative<Config>(r));
    CHECK(std::get<Config>(r).badge_url == "https://github.com/0xsharkboy/nx-discord-rpc");
    env["BADGE_URL"] = "https://example.org/my-relay";
    r = load(env);
    REQUIRE(std::holds_alternative<Config>(r));
    CHECK(std::get<Config>(r).badge_url == "https://example.org/my-relay");
}

TEST_CASE("load_config: BADGE_URL must be an https URL of at most 256 characters") {
    for (const std::string& bad : std::vector<std::string>{"http://example.org", "https://", "example.org", "https://a b",
                                  "https://" + std::string(250, 'a')}) {
        auto env = full();
        env["BADGE_URL"] = bad;
        auto r = load(env);
        REQUIRE(std::holds_alternative<std::string>(r));
        CHECK(std::get<std::string>(r).find("BADGE_URL") != std::string::npos);
        CHECK(std::get<std::string>(r).find(bad) == std::string::npos);
    }
}

TEST_CASE("load_config: BADGE_URL of exactly 256 characters is accepted, PUBLIC_BASE_URL is capped at 200") {
    auto env = full();
    const std::string at_limit = "https://" + std::string(248, 'a');
    REQUIRE(at_limit.size() == 256);
    env["BADGE_URL"] = at_limit;
    auto r = load(env);
    REQUIRE(std::holds_alternative<Config>(r));
    CHECK(std::get<Config>(r).badge_url == at_limit);

    env = full();
    env["PUBLIC_BASE_URL"] = "https://" + std::string(192, 'a');
    REQUIRE(std::holds_alternative<Config>(load(env)));
    env["PUBLIC_BASE_URL"] = "https://" + std::string(193, 'a');
    auto too_long = load(env);
    REQUIRE(std::holds_alternative<std::string>(too_long));
    CHECK(std::get<std::string>(too_long).find("PUBLIC_BASE_URL") != std::string::npos);
}
