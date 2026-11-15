#include <doctest/doctest.h>

#include <atomic>
#include <filesystem>
#include <set>
#include <sqlite3.h>
#include <unistd.h>

#include "crypto.hpp"
#include "fake_backend.hpp"
#include "presence.hpp"

using namespace relay;
using Kind = FakeBackend::Kind;

namespace {
constexpr const char* kTid = "0100A0D02127E000";
constexpr const char* kIconUrl = "https://x.test/icons/0100A0D02127E000.jpg";

struct Fixture {
    std::filesystem::path path;
    std::unique_ptr<Db> db;
    FakeBackend backend;
    std::array<uint8_t, 32> key{};
    int64_t now = 1'700'000'000'000;
    std::set<std::string> published;
    std::unique_ptr<Presence> presence;

    Fixture() {
        static std::atomic<int> n{0};
        path = std::filesystem::temp_directory_path() /
               ("relay_presence_test_" + std::to_string(::getpid()) + "_" + std::to_string(n++) + ".db");
        db = Db::open(path.string());
        key.fill(9);
        add_user("42", "access-42");
        add_user("43", "access-43");
        presence = std::make_unique<Presence>(
            backend, *db, key, "https://x.test",
            [this](const std::string& tid) { return published.count(tid) > 0; }, [this] { return now; });
    }
    ~Fixture() {
        presence.reset();
        db.reset();
        for (const char* s : {"", "-wal", "-shm"}) std::filesystem::remove(path.string() + s);
    }
    void add_user(const std::string& id, const std::string& access) {
        User u;
        u.discord_id = id;
        u.username = "user" + id;
        u.key_hash = "hash" + id;
        u.access_sealed = seal(key, access);
        u.refresh_sealed = seal(key, "refresh-" + id);
        u.access_expires_at = 1'800'000'000;
        db->upsert_user(u);
    }
    void put(const std::string& id, const std::string& name, std::optional<int64_t> elapsed = 30,
             std::optional<std::string> tid = std::string(kTid), const std::string& details = "Chapter 1") {
        presence->put(id, PresenceUpdate{name, details, elapsed, tid});
    }
    void advance(int64_t ms) {
        now += ms;
        presence->tick();
    }
};
}  // namespace

TEST_CASE("presence: first put connects then sets the activity") {
    Fixture f;
    f.put("42", "Zelda", 30);
    f.presence->tick();
    auto calls = f.backend.calls();
    REQUIRE(calls.size() == 2);
    CHECK(calls[0].kind == Kind::Connect);
    CHECK(calls[0].discord_id == "42");
    CHECK(calls[0].token == "access-42");
    CHECK(calls[1].kind == Kind::Set);
    REQUIRE(calls[1].spec);
    CHECK(calls[1].spec->name == "Zelda");
    CHECK(calls[1].spec->details == "Chapter 1");
    CHECK(calls[1].spec->large_text == "Zelda");
    CHECK(calls[1].spec->large_image == "switch_logo");
    CHECK(calls[1].spec->start_unix_s == f.now / 1000 - 30);
    CHECK(f.presence->current("42") == calls[1].spec);
    CHECK(f.backend.run_callbacks_count() == 1);
}

TEST_CASE("presence: a published icon gives the icon URL, upper-cased") {
    Fixture f;
    f.published.insert(kTid);
    f.put("42", "Zelda", 30, std::string("0100a0d02127e000"));
    f.presence->tick();
    auto sets = f.backend.calls(Kind::Set);
    REQUIRE(sets.size() == 1);
    CHECK(sets[0].spec->large_image == kIconUrl);
}

TEST_CASE("presence: no elapsed means no start, no title id means the logo") {
    Fixture f;
    f.put("42", "Home", std::nullopt, std::nullopt, "");
    f.presence->tick();
    auto sets = f.backend.calls(Kind::Set);
    REQUIRE(sets.size() == 1);
    CHECK_FALSE(sets[0].spec->start_unix_s);
    CHECK(sets[0].spec->large_image == "switch_logo");
    CHECK(sets[0].spec->details.empty());
}

TEST_CASE("presence: a burst sends one set carrying the latest state after 5 s") {
    Fixture f;
    f.put("42", "A");
    f.presence->tick();
    f.backend.reset();
    f.now += 1000;
    f.put("42", "B");
    f.presence->tick();
    f.now += 1000;
    f.put("42", "C");
    f.presence->tick();
    f.advance(1000);
    f.advance(1999);
    CHECK(f.backend.calls().empty());
    f.advance(1);
    auto calls = f.backend.calls();
    REQUIRE(calls.size() == 1);
    CHECK(calls[0].kind == Kind::Set);
    CHECK(calls[0].spec->name == "C");
    f.advance(10000);
    CHECK(f.backend.calls().size() == 1);
    CHECK(f.backend.calls(Kind::Connect).empty());
}

TEST_CASE("presence: a heartbeat with the same data does not re-send") {
    Fixture f;
    f.put("42", "Zelda", 30);
    f.presence->tick();
    f.backend.reset();
    f.now += 60000;
    f.put("42", "Zelda", 90);
    f.advance(0);
    f.now += 60000;
    f.put("42", "Zelda", 151);  // 1 s of jitter
    f.advance(10000);
    CHECK(f.backend.calls().empty());
}

TEST_CASE("presence: a start moved by 2 s or more is re-sent") {
    Fixture f;
    f.put("42", "Zelda", 30);
    f.presence->tick();
    f.backend.reset();
    f.now += 60000;
    f.put("42", "Zelda", 88);
    f.presence->tick();
    auto sets = f.backend.calls(Kind::Set);
    REQUIRE(sets.size() == 1);
    CHECK(sets[0].spec->start_unix_s == f.now / 1000 - 88);
}

TEST_CASE("presence: silence clears after 150 s and disconnects 60 s later; a later put reconnects") {
    Fixture f;
    f.put("42", "Zelda");
    f.presence->tick();
    f.backend.reset();
    f.advance(149999);
    CHECK(f.backend.calls().empty());
    f.advance(1);
    auto calls = f.backend.calls();
    REQUIRE(calls.size() == 1);
    CHECK(calls[0].kind == Kind::Clear);
    CHECK_FALSE(f.presence->current("42"));
    f.advance(59999);
    CHECK(f.backend.calls().size() == 1);
    f.advance(1);
    calls = f.backend.calls();
    REQUIRE(calls.size() == 2);
    CHECK(calls[1].kind == Kind::Disconnect);
    f.advance(100000);
    f.backend.reset();
    f.put("42", "Mario");
    f.presence->tick();
    calls = f.backend.calls();
    REQUIRE(calls.size() == 2);
    CHECK(calls[0].kind == Kind::Connect);
    CHECK(calls[1].kind == Kind::Set);
    CHECK(calls[1].spec->name == "Mario");
}

TEST_CASE("presence: an explicit clear reaches the backend at the next tick") {
    Fixture f;
    f.put("42", "Zelda");
    f.presence->tick();
    f.backend.reset();
    f.now += 1000;
    f.presence->clear("42");
    CHECK(f.backend.calls().empty());
    f.presence->tick();
    auto calls = f.backend.calls();
    REQUIRE(calls.size() == 1);
    CHECK(calls[0].kind == Kind::Clear);
    CHECK_FALSE(f.presence->current("42"));
}

TEST_CASE("presence: a put within 60 s of a clear reuses the client") {
    Fixture f;
    f.put("42", "Zelda");
    f.presence->tick();
    f.presence->clear("42");
    f.advance(1000);
    f.backend.reset();
    f.now += 30000;
    f.put("42", "Mario");
    f.advance(0);
    f.advance(60000);
    auto calls = f.backend.calls();
    REQUIRE(calls.size() == 1);
    CHECK(calls[0].kind == Kind::Set);
    CHECK(calls[0].spec->name == "Mario");
}

TEST_CASE("presence: icon_published re-sends to users showing that title only") {
    Fixture f;
    f.put("42", "Zelda", 30, std::string(kTid));
    f.put("43", "Mario", 30, std::string("0100000000010000"));
    f.presence->tick();
    f.backend.reset();
    f.now += 5000;
    f.published.insert(kTid);
    f.presence->icon_published("0100a0d02127e000");
    f.presence->tick();
    auto sets = f.backend.calls(Kind::Set);
    REQUIRE(sets.size() == 1);
    CHECK(sets[0].discord_id == "42");
    CHECK(sets[0].spec->large_image == kIconUrl);
    CHECK(sets[0].spec->name == "Zelda");
    CHECK(f.presence->current("42")->large_image == kIconUrl);
}

TEST_CASE("presence: drop clears and disconnects at the next tick, a later put starts fresh") {
    Fixture f;
    f.put("42", "Zelda");
    f.presence->tick();
    f.backend.reset();
    f.now += 1000;
    f.presence->drop("42");
    f.presence->tick();
    auto calls = f.backend.calls();
    REQUIRE(calls.size() == 2);
    CHECK(calls[0].kind == Kind::Clear);
    CHECK(calls[1].kind == Kind::Disconnect);
    CHECK_FALSE(f.presence->current("42"));
    f.backend.reset();
    f.now += 1000;
    f.put("42", "Mario");
    f.presence->tick();
    calls = f.backend.calls();
    REQUIRE(calls.size() == 2);
    CHECK(calls[0].kind == Kind::Connect);
    CHECK(calls[1].kind == Kind::Set);
}

TEST_CASE("presence: two users each get their own connect") {
    Fixture f;
    f.put("42", "Zelda");
    f.put("43", "Mario");
    f.presence->tick();
    auto c42 = f.backend.calls(Kind::Connect, "42");
    auto c43 = f.backend.calls(Kind::Connect, "43");
    REQUIRE(c42.size() == 1);
    REQUIRE(c43.size() == 1);
    CHECK(c42[0].token == "access-42");
    CHECK(c43[0].token == "access-43");
    CHECK(f.presence->current("42")->name == "Zelda");
    CHECK(f.presence->current("43")->name == "Mario");
}

TEST_CASE("presence: an auth failure marks the link broken and forgets the user") {
    Fixture f;
    f.put("42", "Zelda");
    f.presence->tick();
    f.backend.reset();
    f.backend.lose("42", true);
    CHECK(f.db->user_by_discord_id("42")->link_broken);
    CHECK_FALSE(f.presence->current("42"));
    CHECK(f.backend.calls(Kind::Disconnect, "42").size() == 1);
    f.backend.reset();
    f.now += 1000;
    f.put("42", "Zelda");
    f.advance(60000);
    CHECK(f.backend.calls().empty());
    CHECK_FALSE(f.presence->current("42"));
}

TEST_CASE("presence: a non-auth loss reconnects at most once per 30 s") {
    Fixture f;
    f.put("42", "Zelda");
    f.presence->tick();
    f.backend.reset();
    f.now += 1000;
    f.backend.lose("42", false);
    CHECK_FALSE(f.db->user_by_discord_id("42")->link_broken);
    CHECK(f.backend.calls(Kind::Disconnect, "42").size() == 1);
    f.backend.reset();
    f.put("42", "Zelda");
    f.advance(28999);
    CHECK(f.backend.calls().empty());
    f.advance(1);
    auto calls = f.backend.calls();
    REQUIRE(calls.size() == 2);
    CHECK(calls[0].kind == Kind::Connect);
    CHECK(calls[1].kind == Kind::Set);
    f.backend.reset();
    f.now += 1000;
    f.backend.lose("42", false);
    f.backend.reset();
    f.put("42", "Zelda");
    f.advance(28999);
    CHECK(f.backend.calls().empty());
    f.advance(1);
    CHECK(f.backend.calls(Kind::Connect).size() == 1);
}

TEST_CASE("presence: a loss for an unknown user is ignored") {
    Fixture f;
    f.backend.lose("42", true);
    CHECK_FALSE(f.db->user_by_discord_id("42")->link_broken);
    CHECK(f.backend.calls().empty());
}

TEST_CASE("presence: no connect for a missing, broken or unreadable user") {
    Fixture f;
    f.db->set_link_broken("43", true);
    User u = *f.db->user_by_discord_id("42");
    u.access_sealed = {1, 2, 3};
    f.db->upsert_user(u);
    f.put("42", "Zelda");
    f.put("43", "Mario");
    f.put("44", "Kirby");
    f.presence->tick();
    CHECK(f.backend.calls().empty());
    CHECK_FALSE(f.presence->current("42"));
    CHECK_FALSE(f.presence->current("43"));
    CHECK_FALSE(f.presence->current("44"));
}

TEST_CASE("presence: token_refreshed updates a connected client only") {
    Fixture f;
    f.put("42", "Zelda");
    f.presence->tick();
    f.backend.reset();
    f.db->update_tokens("42", seal(f.key, "access-42-new"), seal(f.key, "refresh-42-new"), 1'900'000'000);
    f.presence->token_refreshed("42");
    f.presence->token_refreshed("43");
    f.presence->tick();
    auto calls = f.backend.calls();
    REQUIRE(calls.size() == 1);
    CHECK(calls[0].kind == Kind::UpdateToken);
    CHECK(calls[0].discord_id == "42");
    CHECK(calls[0].token == "access-42-new");
}

TEST_CASE("presence: current is nullopt for an unknown user") {
    Fixture f;
    CHECK_FALSE(f.presence->current("42"));
}

TEST_CASE("presence: token_refreshed while waiting to reconnect does nothing") {
    Fixture f;
    f.put("42", "Zelda");
    f.presence->tick();
    f.backend.lose("42", false);
    f.backend.reset();
    f.presence->token_refreshed("42");
    f.advance(1000);
    CHECK(f.backend.calls().empty());
}

TEST_CASE("presence: an expired access token waits for the refresher instead of connecting") {
    Fixture f;
    f.db->update_tokens("42", seal(f.key, "access-42"), seal(f.key, "refresh-42"), f.now / 1000);
    f.put("42", "Zelda");
    f.presence->tick();
    f.advance(29999);
    CHECK(f.backend.calls().empty());
    CHECK_FALSE(f.db->user_by_discord_id("42")->link_broken);
    f.db->update_tokens("42", seal(f.key, "access-42-new"), seal(f.key, "refresh-42-new"), 1'900'000'000);
    f.put("42", "Zelda");
    f.advance(1);
    auto calls = f.backend.calls();
    REQUIRE(calls.size() == 2);
    CHECK(calls[0].kind == Kind::Connect);
    CHECK(calls[0].token == "access-42-new");
    CHECK(calls[1].kind == Kind::Set);
}

namespace {
// A second connection hides the users table, so every Db user query throws.
void hide_users_table(const std::filesystem::path& path, bool hide) {
    sqlite3* raw = nullptr;
    REQUIRE(sqlite3_open(path.string().c_str(), &raw) == SQLITE_OK);
    const char* sql = hide ? "ALTER TABLE users RENAME TO users_hidden" : "ALTER TABLE users_hidden RENAME TO users";
    CHECK(sqlite3_exec(raw, sql, nullptr, nullptr, nullptr) == SQLITE_OK);
    sqlite3_close(raw);
}
}  // namespace

TEST_CASE("presence: a db error delays the connect without stopping the tick") {
    Fixture f;
    hide_users_table(f.path, true);
    CHECK_THROWS(f.db->user_by_discord_id("42"));
    f.put("42", "Zelda");
    CHECK_NOTHROW(f.presence->tick());
    CHECK(f.backend.calls().empty());
    CHECK(f.backend.run_callbacks_count() == 1);
    hide_users_table(f.path, false);
    f.put("42", "Zelda");
    f.advance(29999);
    CHECK(f.backend.calls().empty());
    f.advance(1);
    CHECK(f.backend.calls(Kind::Connect, "42").size() == 1);
}

TEST_CASE("presence: a db error on an auth loss still forgets the user") {
    Fixture f;
    f.put("42", "Zelda");
    f.presence->tick();
    hide_users_table(f.path, true);
    CHECK_NOTHROW(f.backend.lose("42", true));
    CHECK_FALSE(f.presence->current("42"));
    CHECK(f.backend.calls(Kind::Disconnect, "42").size() == 1);
    hide_users_table(f.path, false);
}
