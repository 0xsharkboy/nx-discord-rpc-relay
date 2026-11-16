// SPDX-License-Identifier: AGPL-3.0-or-later
#include <doctest/doctest.h>

#include <atomic>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <arpa/inet.h>
#include <cerrno>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <stb_image_write.h>

#include "api.hpp"
#include "crypto.hpp"
#include "fake_backend.hpp"
#include "fake_oauth.hpp"
#include "icons.hpp"
#include "links.hpp"
#include "presence.hpp"
#include "rate_limit.hpp"

using namespace relay;
using json = nlohmann::json;
using Kind = FakeBackend::Kind;
namespace fs = std::filesystem;

namespace {

constexpr const char* kTid = "0100A0D02127E000";
constexpr const char* kAdminKey = "admin-secret-key";

void append_cb(void* ctx, void* data, int size) {
    static_cast<std::string*>(ctx)->append(static_cast<const char*>(data), size);
}

std::string make_jpeg(int w, int h, int seed) {
    std::vector<unsigned char> px(static_cast<size_t>(w) * h * 3);
    for (int y = 0; y < h; ++y)
        for (int x = 0; x < w; ++x) {
            unsigned char* p = &px[(static_cast<size_t>(y) * w + x) * 3];
            p[0] = static_cast<unsigned char>(seed * 40 + (x * 255 / w) / 4);
            p[1] = static_cast<unsigned char>((y * 255 / h) / 4);
            p[2] = static_cast<unsigned char>(seed * 20);
        }
    std::string out;
    stbi_write_jpg_to_func(append_cb, &out, w, h, 3, px.data(), 95);
    return out;
}

std::string make_png(int w, int h) {
    std::vector<unsigned char> px(static_cast<size_t>(w) * h * 3, 120);
    std::string out;
    stbi_write_png_to_func(append_cb, &out, w, h, 3, px.data(), w * 3);
    return out;
}

httplib::Headers bearer(const std::string& token) { return {{"Authorization", "Bearer " + token}}; }

json body_of(const httplib::Result& r) { return json::parse(r->body, nullptr, false); }

void check_error(const httplib::Result& r, int status, const std::string& code) {
    REQUIRE(r);
    CHECK(r->status == status);
    CHECK(r->get_header_value("Content-Type") == "application/json");
    auto j = body_of(r);
    REQUIRE(j.is_object());
    CHECK(j.value("error", "") == code);
    REQUIRE(j.contains("message"));
    CHECK(j["message"].is_string());
    CHECK_FALSE(j["message"].get<std::string>().empty());
}

struct Fixture {
    fs::path root;
    std::atomic<int64_t> now{1'700'000'000'000};
    Config cfg;
    std::unique_ptr<Db> db;
    FakeOAuth oauth;
    FakeBackend backend;
    std::unique_ptr<Icons> icons;
    std::unique_ptr<Links> links;
    std::unique_ptr<Presence> presence;
    std::unique_ptr<RateLimiter> link_limiter, poll_limiter, icon_limiter;
    std::mutex log_mu;
    std::vector<std::string> log_lines;
    std::unique_ptr<Deps> deps;
    httplib::Server svr;
    std::thread server_thread;
    int port = 0;
    std::unique_ptr<httplib::Client> cli;

    explicit Fixture(bool trust_proxy = false, bool with_admin = true) {
        static std::atomic<int> n{0};
        root = fs::temp_directory_path() /
               ("relay_api_test_" + std::to_string(::getpid()) + "_" + std::to_string(n++));
        fs::create_directories(root / "icons");
        cfg.client_id = "1571614802260787280";
        cfg.client_secret = "client-secret";
        cfg.public_base_url = "https://x.test";
        cfg.token_key.fill(7);
        if (with_admin) cfg.admin_key = kAdminKey;
        cfg.publish_threshold = 2;
        cfg.trust_proxy = trust_proxy;

        auto now_ms = [this] { return now.load(); };
        db = Db::open((root / "relay.db").string());
        icons = std::make_unique<Icons>(*db, (root / "icons").string(), cfg.publish_threshold,
                                        [this] { return now.load() / 1000; });
        links = std::make_unique<Links>(oauth, *db, cfg.token_key, now_ms);
        presence = std::make_unique<Presence>(
            backend, *db, cfg.token_key, cfg.public_base_url,
            [this](const std::string& tid) { return icons->published_path(tid).has_value(); }, now_ms);
        icons->on_published = [this](const std::string& tid) { presence->icon_published(tid); };
        icons->on_unpublished = [this](const std::string& tid) { presence->icon_published(tid); };
        links->on_relinked = [this](const std::string& id) { presence->drop(id); };
        link_limiter = std::make_unique<RateLimiter>(10, 3'600'000, now_ms);
        poll_limiter = std::make_unique<RateLimiter>(720, 3'600'000, now_ms);
        icon_limiter = std::make_unique<RateLimiter>(30, 3'600'000, now_ms);
        deps = std::make_unique<Deps>(Deps{
            cfg, *db, *icons, *links, *presence, *link_limiter, *poll_limiter, *icon_limiter,
            [this] { return now.load(); },
            [this](const std::string& line) {
                std::lock_guard lk(log_mu);
                log_lines.push_back(line);
            },
            [this] { return now.load() / 1000; }});
        register_routes(svr, *deps);
        port = svr.bind_to_any_port("127.0.0.1");
        REQUIRE(port > 0);
        server_thread = std::thread([this] { svr.listen_after_bind(); });
        svr.wait_until_ready();
        cli = std::make_unique<httplib::Client>("127.0.0.1", port);
        cli->set_read_timeout(10);
    }

    ~Fixture() {
        svr.stop();
        if (server_thread.joinable()) server_thread.join();
        presence.reset();
        db.reset();
        std::error_code ec;
        fs::remove_all(root, ec);
    }

    std::vector<std::string> logs() {
        std::lock_guard lk(log_mu);
        return log_lines;
    }

    // Runs the device flow to the end and returns the API key.
    std::string link(const std::string& discord_id = "42", const std::string& username = "alice") {
        oauth.poll_results.push_back(
            FakeOAuth::granted(discord_id, username, "access-" + discord_id, "refresh-" + discord_id));
        auto start = cli->Post("/v1/link");
        REQUIRE(start);
        REQUIRE(start->status == 200);
        auto id = body_of(start)["link_id"].get<std::string>();
        now += 5000;
        auto poll = cli->Post("/v1/link/" + id + "/poll");
        REQUIRE(poll);
        REQUIRE(poll->status == 200);
        auto j = body_of(poll);
        REQUIRE(j["state"] == "linked");
        return j["api_key"].get<std::string>();
    }

    httplib::Result put_presence(const std::string& key, const std::string& body) {
        return cli->Put("/v1/presence", bearer(key), body, "application/json");
    }
    httplib::Result put_icon(const std::string& key, const std::string& tid, const std::string& body) {
        return cli->Put("/v1/icons/" + tid, bearer(key), body, "image/jpeg");
    }
};

}  // namespace

TEST_CASE("api: healthz") {
    Fixture f;
    auto r = f.cli->Get("/healthz");
    REQUIRE(r);
    CHECK(r->status == 200);
    CHECK(r->body == "ok");
}

TEST_CASE("api: the link flow gives an api key that works for GET /v1/me") {
    Fixture f;
    f.oauth.poll_results.push_back(FakeOAuth::granted("42", "alice"));
    auto start = f.cli->Post("/v1/link");
    REQUIRE(start);
    REQUIRE(start->status == 200);
    auto s = body_of(start);
    CHECK(s["user_code"] == "ABCD-EFGH");
    CHECK(s["verification_uri_complete"] == "https://discord.com/activate?user_code=ABCD-EFGH");
    CHECK(s["expires_in"] == 300);
    CHECK(s["interval"] == 5);
    auto id = s["link_id"].get<std::string>();
    CHECK_FALSE(id.empty());
    CHECK_FALSE(s.contains("device_code"));
    CHECK(start->body.find("device-code-secret") == std::string::npos);

    auto pending = f.cli->Post("/v1/link/" + id + "/poll");
    REQUIRE(pending);
    CHECK(pending->status == 200);
    CHECK(body_of(pending) == json{{"state", "pending"}});

    f.now += 5000;
    auto linked = f.cli->Post("/v1/link/" + id + "/poll");
    REQUIRE(linked);
    REQUIRE(linked->status == 200);
    auto l = body_of(linked);
    CHECK(l["state"] == "linked");
    CHECK(l["username"] == "alice");
    auto key = l["api_key"].get<std::string>();
    CHECK_FALSE(key.empty());

    auto me = f.cli->Get("/v1/me", bearer(key));
    REQUIRE(me);
    CHECK(me->status == 200);
    CHECK(me->get_header_value("Content-Type") == "application/json");
    auto m = body_of(me);
    CHECK(m["username"] == "alice");
    CHECK(m["link_broken"] == false);
    CHECK(m["presence"].is_null());

    for (const auto& line : f.logs()) {
        CHECK(line.find(id) == std::string::npos);
        CHECK(line.find(key) == std::string::npos);
    }
    bool redacted = false;
    for (const auto& line : f.logs())
        if (line.find("POST /v1/link/:id/poll 200") != std::string::npos) redacted = true;
    CHECK(redacted);
}

TEST_CASE("api: poll linked JSON carries discord_id and avatar") {
    Fixture f;
    const std::string hash = "0123456789abcdef0123456789abcdef";
    auto link = [&](const std::string& id, const std::optional<std::string>& avatar) {
        f.oauth.poll_results.push_back(FakeOAuth::granted(id, "u" + id, "a" + id, "r" + id, 604800, avatar));
        auto start = f.cli->Post("/v1/link");
        REQUIRE(start);
        auto link_id = body_of(start)["link_id"].get<std::string>();
        f.now += 5000;
        auto poll = f.cli->Post("/v1/link/" + link_id + "/poll");
        REQUIRE(poll);
        REQUIRE(poll->status == 200);
        return body_of(poll);
    };
    auto with = link("42", hash);
    CHECK(with["state"] == "linked");
    CHECK(with["discord_id"] == "42");
    CHECK(with["avatar"] == hash);
    auto without = link("43", std::nullopt);
    CHECK(without["discord_id"] == "43");
    REQUIRE(without.contains("avatar"));
    CHECK(without["avatar"].is_null());
}

TEST_CASE("api: GET /v1/me returns discord_id and avatar") {
    Fixture f;
    const std::string hash = "0123456789abcdef0123456789abcdef";
    auto key = f.link("42", "alice");
    auto key2 = f.link("43", "bob");
    REQUIRE(f.db->update_identity("42", sha256_hex(key), "alice", hash));
    auto m = body_of(f.cli->Get("/v1/me", bearer(key)));
    CHECK(m["discord_id"] == "42");
    CHECK(m["avatar"] == hash);
    auto m2 = body_of(f.cli->Get("/v1/me", bearer(key2)));
    CHECK(m2["discord_id"] == "43");
    REQUIRE(m2.contains("avatar"));
    CHECK(m2["avatar"].is_null());

    f.db->set_link_broken("42", true);
    auto broken = body_of(f.cli->Get("/v1/me", bearer(key)));
    CHECK(broken["link_broken"] == true);
    CHECK(broken["discord_id"] == "42");
    CHECK(broken["avatar"] == hash);
}

TEST_CASE("api: poll states map to JSON and status codes") {
    Fixture f;
    auto start = [&] {
        auto r = f.cli->Post("/v1/link");
        REQUIRE(r);
        REQUIRE(r->status == 200);
        f.now += 5000;
        return body_of(r)["link_id"].get<std::string>();
    };

    f.oauth.poll_results.push_back(FakeOAuth::state(PollState::Denied));
    auto denied = f.cli->Post("/v1/link/" + start() + "/poll");
    REQUIRE(denied);
    CHECK(denied->status == 200);
    CHECK(body_of(denied) == json{{"state", "denied"}});

    f.oauth.poll_results.push_back(FakeOAuth::state(PollState::Expired));
    auto expired = f.cli->Post("/v1/link/" + start() + "/poll");
    REQUIRE(expired);
    CHECK(expired->status == 200);
    CHECK(body_of(expired) == json{{"state", "expired"}});

    f.oauth.poll_results.push_back(FakeOAuth::state(PollState::Error));
    check_error(f.cli->Post("/v1/link/" + start() + "/poll"), 502, "discord_unavailable");

    check_error(f.cli->Post("/v1/link/not-a-real-link/poll"), 404, "unknown_link");
}

TEST_CASE("api: POST /v1/link when Discord is down gives 502") {
    Fixture f;
    f.oauth.device_result.reset();
    check_error(f.cli->Post("/v1/link"), 502, "discord_unavailable");
}

TEST_CASE("api: an exception in a handler gives a JSON 500 without internals") {
    Fixture f;
    auto r = f.cli->Post("/v1/link");
    REQUIRE(r);
    auto id = body_of(r)["link_id"].get<std::string>();
    f.now += 5000;
    f.oauth.throw_on_poll = true;
    auto res = f.cli->Post("/v1/link/" + id + "/poll");
    check_error(res, 500, "internal_error");
    CHECK(res->body.find("poll failed") == std::string::npos);
}

TEST_CASE("api: PUT /v1/presence requires a valid key") {
    Fixture f;
    auto body = R"({"name":"Zelda"})";
    check_error(f.cli->Put("/v1/presence", body, "application/json"), 401, "unauthorized");
    check_error(f.put_presence("not-a-key", body), 401, "unauthorized");
    check_error(f.cli->Put("/v1/presence", {{"Authorization", "Basic abc"}}, body, "application/json"), 401,
                "unauthorized");
    check_error(f.cli->Put("/v1/presence", {{"Authorization", "Bearer "}}, body, "application/json"), 401,
                "unauthorized");
    check_error(f.put_presence(kAdminKey, body), 401, "unauthorized");
}

TEST_CASE("api: PUT /v1/presence validates the body") {
    Fixture f;
    auto key = f.link();
    for (const char* bad : {
             R"({"name":""})",
             R"({"name":"Zelda","elapsed_s":-1})",
             R"({"name":"Zelda","elapsed_s":31536001})",
             R"({"name":"Zelda","elapsed_s":1.5})",
             R"({"name":"Zelda","elapsed_s":"5"})",
             R"({"name":"Zelda","elapsed_s":true})",
             R"({"name":"Zelda","elapsed_s":18446744073709551615})",
             R"({"name":"Zelda","details":5})",
             R"({"name":"Zelda","title_id":"0000000000000000"})",
             R"({"name":"Zelda","title_id":"0100A0D02127E00"})",
             R"({"name":"Zelda","title_id":12})",
             R"({"name":5})",
             R"({"details":"x"})",
             R"(["name"])",
             R"(not json)",
             "",
         }) {
        CAPTURE(bad);
        check_error(f.put_presence(key, bad), 400, "invalid_body");
    }
    check_error(f.put_presence(key, json{{"name", std::string(129, 'a')}}.dump()), 400, "invalid_body");
    check_error(f.put_presence(key, json{{"name", "Z"}, {"details", std::string(129, 'a')}}.dump()), 400,
                "invalid_body");
    check_error(f.put_presence(key, json{{"name", "Z"}, {"pad", std::string(5000, 'a')}}.dump()), 413,
                "too_large");

    auto max_ok = f.put_presence(
        key, json{{"name", std::string(128, 'a')}, {"details", std::string(128, 'b')}, {"elapsed_s", 31536000}}
                 .dump());
    REQUIRE(max_ok);
    CHECK(max_ok->status == 204);
    auto extra = f.put_presence(key, R"({"name":"Zelda","unknown":{"a":1},"elapsed_s":0})");
    REQUIRE(extra);
    CHECK(extra->status == 204);
}

TEST_CASE("api: a valid presence reaches the backend and shows in GET /v1/me") {
    Fixture f;
    auto key = f.link();
    auto r = f.put_presence(key, R"({"name":"Zelda","details":"Chapter 1","elapsed_s":30})");
    REQUIRE(r);
    CHECK(r->status == 204);
    CHECK(r->body.empty());
    f.presence->tick();
    auto sets = f.backend.calls(Kind::Set, "42");
    REQUIRE(sets.size() == 1);
    CHECK(sets[0].spec->name == "Zelda");
    CHECK(sets[0].spec->details == "Chapter 1");
    CHECK(sets[0].spec->start_unix_s == f.now.load() / 1000 - 30);

    auto me = f.cli->Get("/v1/me", bearer(key));
    REQUIRE(me);
    auto m = body_of(me);
    CHECK(m["presence"] == json{{"name", "Zelda"}, {"details", "Chapter 1"}});

    auto del = f.cli->Delete("/v1/presence", bearer(key));
    REQUIRE(del);
    CHECK(del->status == 204);
    f.presence->tick();
    CHECK(f.backend.calls(Kind::Clear, "42").size() == 1);
    CHECK(body_of(f.cli->Get("/v1/me", bearer(key)))["presence"].is_null());
}

TEST_CASE("api: an absent details is sent as empty and a lower-case title id is normalized") {
    Fixture f;
    auto key = f.link();
    auto admin = f.put_icon(kAdminKey, kTid, make_jpeg(256, 256, 1));
    REQUIRE(admin);
    REQUIRE(admin->status == 200);
    auto r = f.put_presence(key, R"({"name":"Zelda","title_id":"0100a0d02127e000"})");
    REQUIRE(r);
    CHECK(r->status == 204);
    f.presence->tick();
    auto sets = f.backend.calls(Kind::Set, "42");
    REQUIRE(sets.size() == 1);
    CHECK(sets[0].spec->details.empty());
    CHECK_FALSE(sets[0].spec->start_unix_s);
    CHECK(sets[0].spec->large_image == std::string("https://x.test/icons/") + kTid + ".jpg");
}

TEST_CASE("api: a broken link gives 409 on PUT presence and shows in GET /v1/me") {
    Fixture f;
    auto key = f.link();
    f.db->set_link_broken("42", true);
    check_error(f.put_presence(key, R"({"name":"Zelda"})"), 409, "link_broken");
    check_error(f.put_presence(key, "not json"), 409, "link_broken");
    auto me = f.cli->Get("/v1/me", bearer(key));
    REQUIRE(me);
    CHECK(me->status == 200);
    CHECK(body_of(me)["link_broken"] == true);
    auto del = f.cli->Delete("/v1/presence", bearer(key));
    REQUIRE(del);
    CHECK(del->status == 204);
    auto vote = f.put_icon(key, kTid, make_jpeg(256, 256, 1));
    REQUIRE(vote);
    CHECK(vote->status == 202);
}

TEST_CASE("api: DELETE /v1/me unlinks and the key stops working") {
    Fixture f;
    auto key = f.link();
    REQUIRE(f.put_presence(key, R"({"name":"Zelda"})")->status == 204);
    f.presence->tick();
    auto del = f.cli->Delete("/v1/me", bearer(key));
    REQUIRE(del);
    CHECK(del->status == 204);
    check_error(f.cli->Get("/v1/me", bearer(key)), 401, "unauthorized");
    check_error(f.cli->Delete("/v1/me", bearer(key)), 401, "unauthorized");
    CHECK(f.oauth.revoked.empty());
    f.links->flush_revocations();
    CHECK(f.oauth.revoked.size() == 2);
    f.presence->tick();
    CHECK(f.backend.calls(Kind::Disconnect, "42").size() == 1);
}

TEST_CASE("api: keyed routes refuse a missing key") {
    Fixture f;
    check_error(f.cli->Get("/v1/me"), 401, "unauthorized");
    check_error(f.cli->Delete("/v1/me"), 401, "unauthorized");
    check_error(f.cli->Delete("/v1/presence"), 401, "unauthorized");
    check_error(f.cli->Put("/v1/icons/0100A0D02127E000", "x", "image/jpeg"), 401, "unauthorized");
}

TEST_CASE("api: two votes publish an icon that is then served") {
    Fixture f;
    auto a = f.link("42", "alice");
    auto b = f.link("43", "bob");
    auto jpg = make_jpeg(256, 256, 1);

    auto first = f.put_icon(a, kTid, jpg);
    REQUIRE(first);
    CHECK(first->status == 202);
    CHECK(body_of(first) == json{{"status", "pending"}, {"votes", 1}, {"needed", 2}});

    check_error(f.cli->Get(std::string("/icons/") + kTid + ".jpg"), 404, "not_found");

    auto second = f.put_icon(b, kTid, jpg);
    REQUIRE(second);
    CHECK(second->status == 200);
    CHECK(body_of(second) == json{{"status", "published"}});

    auto again = f.put_icon(a, kTid, jpg);
    REQUIRE(again);
    CHECK(again->status == 200);
    CHECK(body_of(again) == json{{"status", "already_published"}});

    auto icon = f.cli->Get(std::string("/icons/") + kTid + ".jpg");
    REQUIRE(icon);
    CHECK(icon->status == 200);
    CHECK(icon->get_header_value("Content-Type") == "image/jpeg");
    CHECK(icon->get_header_value("Cache-Control") == "public, max-age=86400");
    REQUIRE(icon->body.size() > 2);
    CHECK(static_cast<unsigned char>(icon->body[0]) == 0xFF);
    CHECK(static_cast<unsigned char>(icon->body[1]) == 0xD8);

    auto lower = f.cli->Get("/icons/0100a0d02127e000.jpg");
    REQUIRE(lower);
    CHECK(lower->status == 200);
}

TEST_CASE("api: malicious icon uploads are refused") {
    Fixture f;
    auto key = f.link();
    check_error(f.put_icon(key, kTid, make_png(256, 256)), 400, "invalid_icon");
    check_error(f.put_icon(key, kTid, make_jpeg(128, 128, 1)), 400, "invalid_icon");
    check_error(f.put_icon(key, kTid, std::string(10 * 1024 * 1024, 'x')), 413, "too_large");
    check_error(f.put_icon(key, kTid, std::string(200'000, 'x')), 413, "too_large");
    check_error(f.put_icon(key, "0000000000000000", make_jpeg(256, 256, 1)), 400, "invalid_icon");
    check_error(f.put_icon(key, "not-a-tid", make_jpeg(256, 256, 1)), 400, "invalid_icon");
    check_error(f.cli->Get("/icons/0000000000000000.jpg"), 404, "not_found");
    check_error(f.cli->Get(std::string("/icons/") + kTid + ".jpg"), 404, "not_found");
    CHECK(fs::is_empty(f.root / "icons"));

    auto other = f.link("43", "bob");
    auto vote = f.put_icon(other, kTid, make_jpeg(256, 256, 1));
    REQUIRE(vote);
    CHECK(vote->status == 202);
    CHECK(body_of(vote) == json{{"status", "pending"}, {"votes", 1}, {"needed", 2}});
    CHECK(fs::is_empty(f.root / "icons"));
}

TEST_CASE("api: admin uploads publish at once, admin delete unpublishes and blocks") {
    Fixture f;
    auto key = f.link();
    auto jpg = make_jpeg(256, 256, 2);

    auto up = f.put_icon(kAdminKey, kTid, jpg);
    REQUIRE(up);
    CHECK(up->status == 200);
    CHECK(body_of(up) == json{{"status", "published"}});
    CHECK(f.cli->Get(std::string("/icons/") + kTid + ".jpg")->status == 200);

    check_error(f.cli->Delete(std::string("/v1/icons/") + kTid, bearer(key)), 401, "unauthorized");
    check_error(f.cli->Delete(std::string("/v1/icons/") + kTid), 401, "unauthorized");

    auto del = f.cli->Delete(std::string("/v1/icons/") + kTid, bearer(kAdminKey));
    REQUIRE(del);
    CHECK(del->status == 204);
    check_error(f.cli->Get(std::string("/icons/") + kTid + ".jpg"), 404, "not_found");
    check_error(f.cli->Delete(std::string("/v1/icons/") + kTid, bearer(kAdminKey)), 404, "not_found");

    check_error(f.put_icon(key, kTid, jpg), 400, "blocked");
}

TEST_CASE("api: admin delete of an icon puts the logo back on presences showing it") {
    Fixture f;
    auto key = f.link();
    REQUIRE(f.put_icon(kAdminKey, kTid, make_jpeg(256, 256, 2))->status == 200);
    REQUIRE(f.put_presence(key, std::string(R"({"name":"Zelda","title_id":")") + kTid + "\"}")->status == 204);
    f.presence->tick();
    REQUIRE(f.presence->current("42"));
    CHECK(f.presence->current("42")->large_image == std::string("https://x.test/icons/") + kTid + ".jpg");

    REQUIRE(f.cli->Delete(std::string("/v1/icons/") + kTid, bearer(kAdminKey))->status == 204);
    f.now += 5000;
    f.backend.reset();
    f.presence->tick();
    auto sets = f.backend.calls(Kind::Set, "42");
    REQUIRE(sets.size() == 1);
    CHECK(sets[0].spec->large_image == "switch_logo");
    CHECK(f.presence->current("42")->large_image == "switch_logo");
}

TEST_CASE("api: admin endpoints are closed when no admin key is configured") {
    Fixture f(false, false);
    check_error(f.put_icon(kAdminKey, kTid, make_jpeg(256, 256, 1)), 401, "unauthorized");
    check_error(f.cli->Delete(std::string("/v1/icons/") + kTid, bearer(kAdminKey)), 401, "unauthorized");
}

TEST_CASE("api: the 11th POST /v1/link from one IP within an hour is refused") {
    Fixture f;
    for (int i = 0; i < 10; ++i) REQUIRE(f.cli->Post("/v1/link")->status == 200);
    auto r = f.cli->Post("/v1/link");
    check_error(r, 429, "rate_limited");
    CHECK(r->get_header_value("Retry-After") == "360");
    f.now += 360'000;
    CHECK(f.cli->Post("/v1/link")->status == 200);
}

TEST_CASE("api: without trust_proxy the rate limit ignores X-Forwarded-For") {
    Fixture f(false);
    for (int i = 0; i < 10; ++i)
        REQUIRE(f.cli->Post("/v1/link", {{"X-Forwarded-For", "10.0.0." + std::to_string(i)}}, "", "text/plain")
                    ->status == 200);
    check_error(f.cli->Post("/v1/link", {{"X-Forwarded-For", "10.0.1.1"}}, "", "text/plain"), 429,
                "rate_limited");
}

TEST_CASE("api: with trust_proxy the rate limit keys on the first X-Forwarded-For hop") {
    Fixture f(true);
    for (int i = 0; i < 10; ++i)
        REQUIRE(f.cli->Post("/v1/link", {{"X-Forwarded-For", "1.2.3.4, 10.0.0.1"}}, "", "text/plain")->status ==
                200);
    check_error(f.cli->Post("/v1/link", {{"X-Forwarded-For", " 1.2.3.4 ,172.16.0.1"}}, "", "text/plain"), 429,
                "rate_limited");
    CHECK(f.cli->Post("/v1/link", {{"X-Forwarded-For", "5.6.7.8, 10.0.0.1"}}, "", "text/plain")->status == 200);
    CHECK(f.cli->Post("/v1/link")->status == 200);
}

TEST_CASE("api: icon uploads are limited per key, the admin key is exempt") {
    Fixture f;
    auto a = f.link("42", "alice");
    auto b = f.link("43", "bob");
    for (int i = 0; i < 30; ++i) REQUIRE(f.put_icon(a, kTid, "x")->status == 400);
    auto r = f.put_icon(a, kTid, "x");
    check_error(r, 429, "rate_limited");
    CHECK_FALSE(r->get_header_value("Retry-After").empty());
    CHECK(f.put_icon(b, kTid, "x")->status == 400);
    for (int i = 0; i < 35; ++i) REQUIRE(f.put_icon(kAdminKey, kTid, "x")->status == 400);
}

TEST_CASE("api: generated errors are JSON too") {
    Fixture f;
    check_error(f.cli->Get("/nope"), 404, "not_found");
    check_error(f.cli->Get("/v1/link"), 404, "not_found");
    check_error(f.cli->Post("/v1/presence", R"({"name":"x"})", "application/json"), 404, "not_found");
}

TEST_CASE("api: request logs carry no query string") {
    Fixture f;
    f.cli->Get("/healthz?token=secret-value");
    for (const auto& line : f.logs()) CHECK(line.find("secret-value") == std::string::npos);
    bool seen = false;
    for (const auto& line : f.logs())
        if (line.find("GET /healthz 200") != std::string::npos) seen = true;
    CHECK(seen);
}

TEST_CASE("api: with trust_proxy an oversized first hop falls back to the peer address") {
    Fixture f(true);
    for (int i = 0; i < 10; ++i)
        REQUIRE(f.cli->Post("/v1/link", {{"X-Forwarded-For", std::string(46 + i, 'a')}}, "", "text/plain")
                    ->status == 200);
    check_error(f.cli->Post("/v1/link"), 429, "rate_limited");
}

TEST_CASE("api: IPv6 clients are limited per /64, IPv4-mapped addresses as IPv4") {
    Fixture f(true);
    for (int i = 0; i < 10; ++i)
        REQUIRE(f.cli->Post("/v1/link", {{"X-Forwarded-For", "2001:db8:1:2::" + std::to_string(i + 1)}}, "",
                            "text/plain")
                    ->status == 200);
    check_error(f.cli->Post("/v1/link", {{"X-Forwarded-For", "2001:db8:1:2:ffff:1:2:3"}}, "", "text/plain"), 429,
                "rate_limited");
    CHECK(f.cli->Post("/v1/link", {{"X-Forwarded-For", "2001:db8:1:3::1"}}, "", "text/plain")->status == 200);

    for (int i = 0; i < 10; ++i)
        REQUIRE(f.cli->Post("/v1/link", {{"X-Forwarded-For", "9.9.9.9"}}, "", "text/plain")->status == 200);
    check_error(f.cli->Post("/v1/link", {{"X-Forwarded-For", "::ffff:9.9.9.9"}}, "", "text/plain"), 429,
                "rate_limited");
}

TEST_CASE("api: a chunked body is refused and the connection is closed") {
    Fixture f;
    auto r = f.cli->Put(
        "/v1/presence", bearer("x"),
        [](size_t, httplib::DataSink& sink) {
            sink.write("{}", 2);
            sink.done();
            return true;
        },
        "application/json");
    check_error(r, 411, "length_required");
    CHECK(r->get_header_value("Connection") == "close");
}

namespace {
// Everything the server sends until it closes the connection or `timeout_s` passes without data.
struct RawRead {
    std::string data;
    bool closed = false;
};

RawRead raw_read(int fd, int timeout_s) {
    timeval tv{timeout_s, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    RawRead out;
    char buf[4096];
    for (;;) {
        ssize_t n = ::recv(fd, buf, sizeof buf, 0);
        if (n > 0) {
            out.data.append(buf, static_cast<size_t>(n));
            continue;
        }
        out.closed = n == 0 || errno == ECONNRESET;
        return out;
    }
}

int count_of(const std::string& hay, const std::string& needle) {
    int n = 0;
    for (auto pos = hay.find(needle); pos != std::string::npos; pos = hay.find(needle, pos + 1)) ++n;
    return n;
}
}  // namespace

TEST_CASE("api: chunk bytes after a 411 are never parsed as a second request") {
    Fixture f;
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(fd >= 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(f.port));
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    REQUIRE(::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr) == 0);

    const std::string head =
        "PUT /v1/presence HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n"
        "Content-Type: application/json\r\n\r\n";
    REQUIRE(::send(fd, head.data(), head.size(), MSG_NOSIGNAL) == static_cast<ssize_t>(head.size()));
    auto first = raw_read(fd, 1);
    CHECK(first.data.find("HTTP/1.1 411") == 0);

    // The unread chunked body arrives after the response: it must not reach the router.
    const std::string body = "GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n";
    ::send(fd, body.data(), body.size(), MSG_NOSIGNAL);
    auto rest = first.closed ? RawRead{{}, true} : raw_read(fd, 2);
    ::close(fd);

    CHECK(count_of(first.data + rest.data, "HTTP/1.1 ") == 1);
    CHECK(rest.closed);
}

TEST_CASE("api: PUT /v1/presence records activity at most once per hour") {
    Fixture f;
    auto key = f.link();
    const int64_t linked_at = f.db->user_by_discord_id("42")->last_seen_at;
    CHECK(linked_at == f.now.load() / 1000);

    f.now += (kLastSeenResolutionS - 1) * 1000;
    auto r = f.put_presence(key, R"({"name":"Zelda"})");
    REQUIRE(r);
    CHECK(r->status == 204);
    CHECK(f.db->user_by_discord_id("42")->last_seen_at == linked_at);

    f.now += 1000;
    r = f.put_presence(key, R"({"name":"Zelda"})");
    REQUIRE(r);
    CHECK(r->status == 204);
    const int64_t seen = f.now.load() / 1000;
    CHECK(f.db->user_by_discord_id("42")->last_seen_at == seen);

    // GET /v1/me and DELETE /v1/presence are not activity.
    f.now += 2 * kLastSeenResolutionS * 1000;
    f.cli->Get("/v1/me", bearer(key));
    f.cli->Delete("/v1/presence", bearer(key));
    CHECK(f.db->user_by_discord_id("42")->last_seen_at == seen);
}

TEST_CASE("api: a PUT /v1/presence refused for a broken link is not activity") {
    Fixture f;
    auto key = f.link();
    const int64_t linked_at = f.db->user_by_discord_id("42")->last_seen_at;
    f.db->set_link_broken("42", true);
    f.now += 2 * kLastSeenResolutionS * 1000;
    check_error(f.put_presence(key, R"({"name":"Zelda"})"), 409, "link_broken");
    CHECK(f.db->user_by_discord_id("42")->last_seen_at == linked_at);
}

TEST_CASE("api: a PUT /v1/presence refused as invalid or too large is not activity") {
    Fixture f;
    auto key = f.link();
    const int64_t linked_at = f.db->user_by_discord_id("42")->last_seen_at;
    f.now += 2 * kLastSeenResolutionS * 1000;
    check_error(f.put_presence(key, "not json"), 400, "invalid_body");
    check_error(f.put_presence(key, std::string(5000, 'x')), 413, "too_large");
    CHECK(f.db->user_by_discord_id("42")->last_seen_at == linked_at);
}
