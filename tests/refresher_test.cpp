#include <doctest/doctest.h>

#include <atomic>
#include <filesystem>
#include <unistd.h>

#include "crypto.hpp"
#include "fake_backend.hpp"
#include "fake_oauth.hpp"
#include "refresher.hpp"

using namespace relay;
using Kind = FakeBackend::Kind;

namespace {
constexpr int64_t kNow = 1'700'000'000;

RefreshResult refreshed(const std::string& access, const std::string& refresh, int64_t expires_in = 604800) {
    return {RefreshResult::State::Refreshed, Tokens{access, refresh, expires_in, "", ""}};
}
RefreshResult state(RefreshResult::State s) { return {s, std::nullopt}; }

struct Fixture {
    std::filesystem::path path;
    std::unique_ptr<Db> db;
    FakeBackend backend;
    FakeOAuth oauth;
    std::array<uint8_t, 32> key{};
    int64_t now_s = kNow;
    int64_t now_ms = kNow * 1000;
    std::unique_ptr<Presence> presence;
    std::unique_ptr<Refresher> refresher;

    Fixture() {
        static std::atomic<int> n{0};
        path = std::filesystem::temp_directory_path() /
               ("relay_refresher_test_" + std::to_string(::getpid()) + "_" + std::to_string(n++) + ".db");
        db = Db::open(path.string());
        key.fill(5);
        presence = std::make_unique<Presence>(
            backend, *db, key, "https://x.test", [](const std::string&) { return false; },
            [this] { return now_ms; });
        refresher = std::make_unique<Refresher>(oauth, *db, key, *presence, [this] { return now_s; });
    }
    ~Fixture() {
        refresher.reset();
        presence.reset();
        db.reset();
        for (const char* s : {"", "-wal", "-shm"}) std::filesystem::remove(path.string() + s);
    }
    void add_user(const std::string& id, int64_t expires_at) {
        User u;
        u.discord_id = id;
        u.username = "user" + id;
        u.key_hash = "hash" + id;
        u.access_sealed = seal(key, "access-" + id);
        u.refresh_sealed = seal(key, "refresh-" + id);
        u.access_expires_at = expires_at;
        db->upsert_user(u);
    }
    void connect(const std::string& id) {
        presence->put(id, PresenceUpdate{"Game", "Details", 10, std::nullopt});
        presence->tick();
        backend.reset();
    }
};
}  // namespace

TEST_CASE("refresher: a user expiring within a day is refreshed and the tokens stored") {
    Fixture f;
    f.add_user("42", kNow + 3600);
    f.connect("42");
    f.oauth.refresh_results.push_back(refreshed("access-new", "refresh-new", 1000));

    f.refresher->run_once();

    CHECK(f.oauth.refreshed_tokens == std::vector<std::string>{"refresh-42"});
    auto u = f.db->user_by_discord_id("42");
    REQUIRE(u);
    CHECK(open(f.key, u->access_sealed) == std::optional<std::string>("access-new"));
    CHECK(open(f.key, u->refresh_sealed) == std::optional<std::string>("refresh-new"));
    CHECK(u->access_expires_at == kNow + 1000);
    CHECK_FALSE(u->link_broken);

    f.presence->tick();
    auto updates = f.backend.calls(Kind::UpdateToken, "42");
    REQUIRE(updates.size() == 1);
    CHECK(updates[0].token == "access-new");
}

TEST_CASE("refresher: a user expiring in three days is untouched") {
    Fixture f;
    f.add_user("42", kNow + 3 * 86400);

    f.refresher->run_once();

    CHECK(f.oauth.refresh_calls == 0);
    auto u = f.db->user_by_discord_id("42");
    CHECK(open(f.key, u->access_sealed) == std::optional<std::string>("access-42"));
    CHECK(u->access_expires_at == kNow + 3 * 86400);
}

TEST_CASE("refresher: a revoked grant breaks the link and drops the user") {
    Fixture f;
    f.add_user("42", kNow + 3600);
    f.connect("42");
    f.oauth.refresh_results.push_back(state(RefreshResult::State::Revoked));

    CHECK_NOTHROW(f.refresher->run_once());

    CHECK(f.db->user_by_discord_id("42")->link_broken);
    f.presence->tick();
    CHECK(f.backend.calls(Kind::Disconnect, "42").size() == 1);
    CHECK(f.backend.calls(Kind::UpdateToken).empty());
}

TEST_CASE("refresher: a transient failure leaves the user untouched and retries next run") {
    Fixture f;
    f.add_user("42", kNow + 3600);
    f.oauth.refresh_results.push_back(state(RefreshResult::State::Transient));

    f.refresher->run_once();

    auto u = f.db->user_by_discord_id("42");
    CHECK_FALSE(u->link_broken);
    CHECK(u->access_expires_at == kNow + 3600);
    CHECK(open(f.key, u->refresh_sealed) == std::optional<std::string>("refresh-42"));

    f.oauth.refresh_results.push_back(refreshed("a2", "r2"));
    f.refresher->run_once();
    CHECK(f.oauth.refresh_calls == 2);
    CHECK(open(f.key, f.db->user_by_discord_id("42")->access_sealed) == std::optional<std::string>("a2"));
}

TEST_CASE("refresher: a broken link is not refreshed again") {
    Fixture f;
    f.add_user("42", kNow + 3600);
    f.oauth.refresh_results.push_back(state(RefreshResult::State::Revoked));

    f.refresher->run_once();
    f.refresher->run_once();

    CHECK(f.oauth.refresh_calls == 1);
}

TEST_CASE("refresher: an unreadable stored refresh token counts as revoked") {
    Fixture f;
    f.add_user("42", kNow + 3600);
    User u = *f.db->user_by_discord_id("42");
    u.refresh_sealed = {1, 2, 3};
    f.db->upsert_user(u);

    CHECK_NOTHROW(f.refresher->run_once());

    CHECK(f.oauth.refresh_calls == 0);
    CHECK(f.db->user_by_discord_id("42")->link_broken);
}

TEST_CASE("refresher: an exception for one user does not stop the next") {
    Fixture f;
    f.add_user("42", kNow + 3600);
    f.add_user("43", kNow + 3600);
    f.oauth.throw_on_refresh_token = "refresh-42";
    f.oauth.refresh_default = refreshed("fresh", "fresh-r");

    CHECK_NOTHROW(f.refresher->run_once());

    CHECK(f.oauth.refresh_calls == 2);
    CHECK(open(f.key, f.db->user_by_discord_id("43")->access_sealed) == std::optional<std::string>("fresh"));
    CHECK_FALSE(f.db->user_by_discord_id("42")->link_broken);
}

TEST_CASE("refresher: rejected client credentials break no link and end the run") {
    Fixture f;
    f.add_user("42", kNow + 3600);
    f.add_user("43", kNow + 3600);
    f.connect("42");
    f.oauth.refresh_default = state(RefreshResult::State::ClientError);

    CHECK_NOTHROW(f.refresher->run_once());

    CHECK(f.oauth.refresh_calls == 1);
    for (const char* id : {"42", "43"}) {
        auto u = f.db->user_by_discord_id(id);
        CHECK_FALSE(u->link_broken);
        CHECK(open(f.key, u->refresh_sealed) == std::optional<std::string>(std::string("refresh-") + id));
    }
    f.presence->tick();
    CHECK(f.backend.calls(Kind::Disconnect).empty());

    f.oauth.refresh_default = refreshed("a2", "r2");
    f.refresher->run_once();
    CHECK(f.oauth.refresh_calls == 3);
}
