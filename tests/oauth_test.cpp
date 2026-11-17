// SPDX-License-Identifier: AGPL-3.0-or-later
#include <doctest/doctest.h>

#include <array>
#include <string>

#include "crypto.hpp"
#include "oauth.hpp"

using namespace relay;

namespace {
std::string b64(const std::string& s) {
    return base64url_encode({reinterpret_cast<const uint8_t*>(s.data()), s.size()});
}
std::string jwt(const std::string& payload) { return b64(R"({"alg":"none"})") + "." + b64(payload) + ".sig"; }
std::string ok_body(const std::string& id_token_field) {
    return R"({"access_token":"at","refresh_token":"rt","expires_in":604800)" + id_token_field + "}";
}
}  // namespace

TEST_CASE("parse_token_response maps device flow errors") {
    CHECK(parse_token_response(400, R"({"error":"authorization_pending"})").state == PollState::Pending);
    CHECK(parse_token_response(400, R"({"error":"slow_down"})").state == PollState::SlowDown);
    CHECK(parse_token_response(400, R"({"error":"expired_token"})").state == PollState::Expired);
    CHECK(parse_token_response(400, R"({"error":"access_denied"})").state == PollState::Denied);
    CHECK(parse_token_response(400, R"({"error":"invalid_request"})").state == PollState::Error);
    CHECK(parse_token_response(429, "").state == PollState::SlowDown);
}

TEST_CASE("parse_token_response grants with identity") {
    auto id = jwt(R"({"sub":"123","preferred_username":"test_rpc"})");
    auto r = parse_token_response(200, ok_body(R"(,"id_token":")" + id + "\""));
    REQUIRE(r.state == PollState::Granted);
    REQUIRE(r.tokens);
    CHECK(r.tokens->access_token == "at");
    CHECK(r.tokens->refresh_token == "rt");
    CHECK(r.tokens->expires_in == 604800);
    CHECK(r.tokens->discord_id == "123");
    CHECK(r.tokens->username == "test_rpc");
}

TEST_CASE("parse_token_response grants without identity") {
    auto r = parse_token_response(200, ok_body(""));
    REQUIRE(r.state == PollState::Granted);
    REQUIRE(r.tokens);
    CHECK(r.tokens->access_token == "at");
    CHECK(r.tokens->refresh_token == "rt");
    CHECK(r.tokens->expires_in == 604800);
    CHECK(r.tokens->discord_id.empty());
    CHECK(r.tokens->username.empty());

    auto bad = parse_token_response(200, ok_body(R"(,"id_token":"garbage")"));
    REQUIRE(bad.state == PollState::Granted);
    REQUIRE(bad.tokens);
    CHECK(bad.tokens->discord_id.empty());
    CHECK(bad.tokens->username.empty());
}

TEST_CASE("parse_token_response errors") {
    CHECK(parse_token_response(200, R"({"access_token":"at","expires_in":1})").state == PollState::Error);
    CHECK(parse_token_response(200, "not json").state == PollState::Error);
    CHECK(parse_token_response(500, "").state == PollState::Error);
    CHECK(parse_token_response(0, "").state == PollState::Error);
    CHECK(parse_token_response(400, "not json").state == PollState::Error);
}

TEST_CASE("id_token_identity") {
    auto r = id_token_identity(jwt(R"({"sub":"42","preferred_username":"bob"})"));
    REQUIRE(r);
    CHECK(r->first == "42");
    CHECK(r->second == "bob");
    auto no_name = id_token_identity(jwt(R"({"sub":"42"})"));
    REQUIRE(no_name);
    CHECK(no_name->second.empty());
    auto padded = b64(R"({"sub":"7"})");
    padded.append((4 - padded.size() % 4) % 4, '=');
    CHECK(id_token_identity("x." + padded + ".y"));
    CHECK_FALSE(id_token_identity("garbage"));
    CHECK_FALSE(id_token_identity(""));
    CHECK_FALSE(id_token_identity("a.!!!.c"));
    CHECK_FALSE(id_token_identity(jwt("not json")));
    CHECK_FALSE(id_token_identity(jwt(R"({"preferred_username":"x"})")));
    CHECK_FALSE(id_token_identity(jwt(R"({"sub":123})")));
}

TEST_CASE("parse_refresh_response") {
    auto r = parse_refresh_response(200, ok_body(""));
    CHECK(r.state == RefreshResult::State::Refreshed);
    REQUIRE(r.tokens);
    CHECK(r.tokens->access_token == "at");
    CHECK(r.tokens->discord_id.empty());

    auto id = jwt(R"({"sub":"123","preferred_username":"u"})");
    auto with_id = parse_refresh_response(200, ok_body(R"(,"id_token":")" + id + "\""));
    REQUIRE(with_id.tokens);
    CHECK(with_id.tokens->discord_id == "123");
    CHECK(with_id.tokens->username == "u");

    CHECK(parse_refresh_response(400, R"({"error":"invalid_grant"})").state == RefreshResult::State::Revoked);
    CHECK(parse_refresh_response(401, "").state == RefreshResult::State::Revoked);
    CHECK(parse_refresh_response(401, R"({"error":"invalid_grant"})").state == RefreshResult::State::Revoked);
    CHECK(parse_refresh_response(401, R"({"error":"invalid_token"})").state == RefreshResult::State::Revoked);
    CHECK(parse_refresh_response(401, R"({"error":"invalid_client"})").state == RefreshResult::State::ClientError);
    CHECK(parse_refresh_response(400, R"({"error":"invalid_client"})").state == RefreshResult::State::ClientError);
    CHECK(parse_refresh_response(400, R"({"error":"unauthorized_client"})").state ==
          RefreshResult::State::ClientError);
    CHECK(parse_refresh_response(401, R"({"error":"unauthorized_client"})").state ==
          RefreshResult::State::ClientError);
    CHECK(parse_refresh_response(400, R"({"error":"invalid_request"})").state == RefreshResult::State::Transient);
    CHECK(parse_refresh_response(500, "").state == RefreshResult::State::Transient);
    CHECK(parse_refresh_response(429, "").state == RefreshResult::State::Transient);
    CHECK(parse_refresh_response(0, "").state == RefreshResult::State::Transient);
    CHECK(parse_refresh_response(200, R"({"refresh_token":"rt","expires_in":1})").state ==
          RefreshResult::State::Transient);
    CHECK(parse_refresh_response(200, "garbage").state == RefreshResult::State::Transient);
    CHECK_FALSE(parse_refresh_response(500, "").tokens);
}

TEST_CASE("parse_device_response") {
    auto d = parse_device_response(200,
        R"({"device_code":"dc","user_code":"UC","verification_uri":"https://d/x","verification_uri_complete":"https://d/x?c=1","expires_in":600,"interval":5})");
    REQUIRE(d);
    CHECK(d->device_code == "dc");
    CHECK(d->verification_uri_complete == "https://d/x?c=1");
    CHECK(d->interval == 5);
    auto f = parse_device_response(200,
        R"({"device_code":"dc","user_code":"UC","verification_uri":"https://d/x","expires_in":600})");
    REQUIRE(f);
    CHECK(f->verification_uri_complete == "https://d/x?user_code=UC");
    CHECK(f->interval == 5);
    CHECK_FALSE(parse_device_response(500, ""));
    CHECK_FALSE(parse_device_response(200, "{}"));
    CHECK_FALSE(parse_device_response(0, ""));
}

TEST_CASE("parse_identity_response") {
    const char* real =
        R"({"application":{"id":"1234567890123456789","name":"app"},"expires":"2026-11-23T00:00:00+00:00","scopes":["openid","sdk.social_layer_presence"],"user":{"id":"123","username":"test_rpc","global_name":null}})";
    auto r = parse_identity_response(200, real, "1234567890123456789");
    REQUIRE(r);
    CHECK(r->discord_id == "123");
    CHECK(r->username == "test_rpc");

    CHECK_FALSE(parse_identity_response(200, real, "999"));
    CHECK_FALSE(parse_identity_response(401, real, "1234567890123456789"));
    CHECK_FALSE(parse_identity_response(0, "", "1234567890123456789"));
    CHECK_FALSE(parse_identity_response(200, R"({"application":{"id":"1"}})", "1"));
    CHECK_FALSE(parse_identity_response(200, R"({"user":{"id":""}})", "1"));
    CHECK_FALSE(parse_identity_response(200, R"({"user":{"id":123}})", "1"));
    CHECK_FALSE(parse_identity_response(200, R"({"user":"x"})", "1"));
    CHECK_FALSE(parse_identity_response(200, "garbage", "1"));
    CHECK_FALSE(parse_identity_response(200, "[]", "1"));

    auto no_app = parse_identity_response(200, R"({"user":{"id":"5"}})", "1");
    REQUIRE(no_app);
    CHECK(no_app->discord_id == "5");
    CHECK(no_app->username.empty());
}

TEST_CASE("parse_identity_response reads the avatar hash") {
    auto with = [](const char* avatar) {
        return std::string(R"({"user":{"id":"5","username":"u","avatar":)") + avatar + "}}";
    };
    CHECK(parse_identity_response(200, with(R"("0123456789abcdef0123456789abcdef")"), "1")->avatar ==
          "0123456789abcdef0123456789abcdef");
    CHECK(parse_identity_response(200, with(R"("a_0123456789abcdef0123456789abcdef")"), "1")->avatar ==
          "a_0123456789abcdef0123456789abcdef");
    CHECK_FALSE(parse_identity_response(200, with("null"), "1")->avatar);
    CHECK_FALSE(parse_identity_response(200, with(R"("../x")"), "1")->avatar);
    CHECK_FALSE(parse_identity_response(200, with(R"("0123456789ABCDEF0123456789ABCDEF")"), "1")->avatar);
    CHECK_FALSE(parse_identity_response(200, with("12"), "1")->avatar);
    CHECK_FALSE(parse_identity_response(200, R"({"user":{"id":"5"}})", "1")->avatar);
}
