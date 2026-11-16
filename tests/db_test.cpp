// SPDX-License-Identifier: AGPL-3.0-or-later
#include <doctest/doctest.h>

#include <atomic>
#include <ctime>
#include <filesystem>
#include <stdexcept>
#include <unistd.h>
#include <string>

#include <sqlite3.h>

#include "db.hpp"

using namespace relay;

namespace {
struct TempDb {
    std::filesystem::path path;
    TempDb() {
        static std::atomic<int> n{0};
        path = std::filesystem::temp_directory_path() /
               ("relay_db_test_" + std::to_string(::getpid()) + "_" + std::to_string(n++) + ".db");
        cleanup();
    }
    ~TempDb() { cleanup(); }
    void cleanup() {
        for (const char* s : {"", "-wal", "-shm"})
            std::filesystem::remove(path.string() + s);
    }
    std::unique_ptr<Db> open() const { return Db::open(path.string()); }
};

User make_user(const std::string& id, const std::string& hash) {
    User u;
    u.discord_id = id;
    u.username = "name-" + id;
    u.key_hash = hash;
    u.access_sealed = {1, 2, 3};
    u.refresh_sealed = {4, 5, 6, 7};
    u.access_expires_at = 1000;
    return u;
}
}  // namespace

TEST_CASE("db: upsert then lookup by key hash and discord id") {
    TempDb t;
    auto db = t.open();
    db->upsert_user(make_user("1", "h1"));
    auto a = db->user_by_key_hash("h1");
    REQUIRE(a);
    CHECK(a->discord_id == "1");
    CHECK(a->username == "name-1");
    CHECK(a->access_sealed == std::vector<uint8_t>{1, 2, 3});
    CHECK(a->refresh_sealed == std::vector<uint8_t>{4, 5, 6, 7});
    CHECK(a->access_expires_at == 1000);
    CHECK_FALSE(a->link_broken);
    auto b = db->user_by_discord_id("1");
    REQUIRE(b);
    CHECK(b->key_hash == "h1");
    CHECK_FALSE(db->user_by_discord_id("2"));
    CHECK_FALSE(db->user_by_key_hash("nope"));
}

TEST_CASE("db: upsert with a new key hash invalidates the old one and replaces every field") {
    TempDb t;
    auto db = t.open();
    auto u = make_user("1", "old");
    u.link_broken = true;
    db->upsert_user(u);
    auto n = make_user("1", "new");
    n.username = "renamed";
    n.access_sealed = {9};
    n.refresh_sealed = {};
    n.access_expires_at = 5;
    db->upsert_user(n);
    CHECK_FALSE(db->user_by_key_hash("old"));
    auto got = db->user_by_key_hash("new");
    REQUIRE(got);
    CHECK(got->username == "renamed");
    CHECK(got->access_sealed == std::vector<uint8_t>{9});
    CHECK(got->refresh_sealed.empty());
    CHECK(got->access_expires_at == 5);
    CHECK_FALSE(got->link_broken);
}

TEST_CASE("db: delete_user") {
    TempDb t;
    auto db = t.open();
    db->upsert_user(make_user("1", "h1"));
    CHECK(db->delete_user("1", "h1"));
    CHECK_FALSE(db->user_by_discord_id("1"));
    CHECK_FALSE(db->user_by_key_hash("h1"));
    CHECK_FALSE(db->delete_user("1", "h1"));
}

TEST_CASE("db: delete_user with a stale key hash keeps the row and its votes") {
    TempDb t;
    auto db = t.open();
    db->upsert_user(make_user("1", "h2"));
    CHECK(db->add_vote("T", "S", "1", 10) == 1);
    CHECK_FALSE(db->delete_user("1", "h1"));
    CHECK(db->user_by_key_hash("h2"));
    CHECK(db->add_vote("T", "S", "2", 11) == 2);
}

TEST_CASE("db: delete_user also removes that user's icon votes") {
    TempDb t;
    auto db = t.open();
    db->upsert_user(make_user("1", "h1"));
    db->upsert_user(make_user("2", "h2"));
    CHECK(db->add_vote("T", "S", "1", 10) == 1);
    CHECK(db->add_vote("T", "S", "2", 10) == 2);
    CHECK(db->add_vote("U", "S", "1", 10) == 1);
    CHECK(db->delete_user("1", "h1"));
    CHECK(db->add_vote("T", "S", "2", 11) == 1);
    CHECK(db->add_vote("U", "S", "3", 11) == 1);
}

TEST_CASE("db: link_broken round trip") {
    TempDb t;
    auto db = t.open();
    db->upsert_user(make_user("1", "h1"));
    db->set_link_broken("1", true);
    CHECK(db->user_by_discord_id("1")->link_broken);
    db->set_link_broken("1", false);
    CHECK_FALSE(db->user_by_discord_id("1")->link_broken);
}

TEST_CASE("db: update_tokens") {
    TempDb t;
    auto db = t.open();
    db->upsert_user(make_user("1", "h1"));
    const std::vector<uint8_t> a{10, 11}, r{12};
    CHECK(db->update_tokens("1", "h1", a, r, 4242));
    auto u = db->user_by_discord_id("1");
    REQUIRE(u);
    CHECK(u->access_sealed == a);
    CHECK(u->refresh_sealed == r);
    CHECK(u->access_expires_at == 4242);
    CHECK(u->key_hash == "h1");
}

TEST_CASE("db: token and link_broken updates are refused once the key hash changed") {
    TempDb t;
    auto db = t.open();
    db->upsert_user(make_user("1", "h1"));
    db->upsert_user(make_user("1", "h2"));
    const std::vector<uint8_t> a{10, 11}, r{12};
    CHECK_FALSE(db->update_tokens("1", "h1", a, r, 4242));
    CHECK_FALSE(db->break_link("1", "h1"));
    auto u = db->user_by_discord_id("1");
    CHECK(u->access_sealed == std::vector<uint8_t>{1, 2, 3});
    CHECK(u->access_expires_at == 1000);
    CHECK_FALSE(u->link_broken);
    CHECK(db->break_link("1", "h2"));
    CHECK(db->user_by_discord_id("1")->link_broken);
    CHECK_FALSE(db->update_tokens("2", "h2", a, r, 1));
}

TEST_CASE("db: users_expiring_before is strict and skips broken links") {
    TempDb t;
    auto db = t.open();
    auto a = make_user("a", "ha");
    a.access_expires_at = 100;
    auto b = make_user("b", "hb");
    b.access_expires_at = 200;
    auto c = make_user("c", "hc");
    c.access_expires_at = 50;
    c.link_broken = true;
    db->upsert_user(a);
    db->upsert_user(b);
    db->upsert_user(c);
    auto r = db->users_expiring_before(200);
    REQUIRE(r.size() == 1);
    CHECK(r[0].discord_id == "a");
    CHECK(db->users_expiring_before(201).size() == 2);
    CHECK(db->users_expiring_before(100).empty());
}

TEST_CASE("db: votes count distinct voters per (title, hash)") {
    TempDb t;
    auto db = t.open();
    CHECK(db->add_vote("T1", "H1", "u1", 10) == 1);
    CHECK(db->add_vote("T1", "H1", "u1", 11) == 1);
    CHECK(db->add_vote("T1", "H1", "u2", 12) == 2);
    CHECK(db->add_vote("T1", "H2", "u1", 13) == 1);
    CHECK(db->add_vote("T2", "H1", "u1", 14) == 1);
}

TEST_CASE("db: a repeated vote does not refresh its timestamp") {
    TempDb t;
    auto db = t.open();
    db->add_vote("T1", "H1", "u1", 10);
    db->add_vote("T1", "H1", "u1", 1000);
    db->expire_votes(500);
    CHECK(db->add_vote("T1", "H1", "u2", 1000) == 1);
}

TEST_CASE("db: expire_votes removes only older votes") {
    TempDb t;
    auto db = t.open();
    db->add_vote("T1", "H1", "u1", 10);
    db->add_vote("T1", "H1", "u2", 100);
    db->expire_votes(100);
    CHECK(db->add_vote("T1", "H1", "u3", 200) == 2);
    db->expire_votes(1000);
    CHECK(db->add_vote("T1", "H1", "u4", 2000) == 1);
}

TEST_CASE("db: publish, replace, unpublish") {
    TempDb t;
    auto db = t.open();
    CHECK_FALSE(db->published_icon("T1"));
    db->publish_icon("T1", "H1", 50);
    auto p = db->published_icon("T1");
    REQUIRE(p);
    CHECK(p->title_id == "T1");
    CHECK(p->sha256 == "H1");
    CHECK(p->published_at == 50);
    db->publish_icon("T1", "H2", 60);
    CHECK(db->published_icon("T1")->sha256 == "H2");
    CHECK(db->published_icon("T1")->published_at == 60);
    db->unpublish_icon("T1");
    CHECK_FALSE(db->published_icon("T1"));
    db->unpublish_icon("T1");
}

TEST_CASE("db: blocklist") {
    TempDb t;
    auto db = t.open();
    CHECK_FALSE(db->is_blocked("H1"));
    db->block_hash("H1");
    db->block_hash("H1");
    CHECK(db->is_blocked("H1"));
    CHECK_FALSE(db->is_blocked("H2"));
}

TEST_CASE("db: reopening keeps data") {
    TempDb t;
    {
        auto db = t.open();
        db->upsert_user(make_user("1", "h1"));
        db->publish_icon("T1", "H1", 5);
        db->add_vote("T1", "H1", "u1", 5);
        db->block_hash("B");
    }
    auto db = t.open();
    CHECK(db->user_by_key_hash("h1"));
    CHECK(db->published_icon("T1"));
    CHECK(db->is_blocked("B"));
    CHECK(db->add_vote("T1", "H1", "u2", 6) == 2);
}

TEST_CASE("db: open fails with runtime_error on an unusable path") {
    CHECK_THROWS_AS(Db::open("/nonexistent-dir-xyz/sub/x.db"), std::runtime_error);
}

TEST_CASE("db: empty blobs and strings bind as empty values, not NULL") {
    TempDb t;
    auto db = t.open();
    User u;
    u.discord_id = "1";
    u.key_hash = "h1";
    REQUIRE_NOTHROW(db->upsert_user(u));
    auto got = db->user_by_discord_id("1");
    REQUIRE(got);
    CHECK(got->username.empty());
    CHECK(got->access_sealed.empty());
    CHECK(got->refresh_sealed.empty());
    db->upsert_user(make_user("2", "h2"));
    REQUIRE_NOTHROW(db->update_tokens("2", "h2", std::span<const uint8_t>{}, std::span<const uint8_t>{}, 7));
    auto two = db->user_by_discord_id("2");
    REQUIRE(two);
    CHECK(two->access_sealed.empty());
    CHECK(two->refresh_sealed.empty());
    CHECK(two->access_expires_at == 7);
    CHECK_FALSE(db->user_by_key_hash(std::string_view{}));
    CHECK_FALSE(db->is_blocked(std::string_view{}));
}

TEST_CASE("db: last_seen_at is stored by upsert and replaced on relink") {
    TempDb t;
    auto db = t.open();
    auto u = make_user("1", "old");
    u.last_seen_at = 100;
    db->upsert_user(u);
    CHECK(db->user_by_key_hash("old")->last_seen_at == 100);
    auto n = make_user("1", "new");
    n.last_seen_at = 900;
    db->upsert_user(n);
    CHECK(db->user_by_key_hash("new")->last_seen_at == 900);
}

TEST_CASE("db: touch_user writes at most once per resolution window and only for the current key") {
    TempDb t;
    auto db = t.open();
    auto u = make_user("1", "h1");
    u.last_seen_at = 10'000;
    db->upsert_user(u);
    CHECK_FALSE(db->touch_user("1", "h1", 10'000 + kLastSeenResolutionS - 1));
    CHECK(db->user_by_discord_id("1")->last_seen_at == 10'000);
    CHECK(db->touch_user("1", "h1", 10'000 + kLastSeenResolutionS));
    CHECK(db->user_by_discord_id("1")->last_seen_at == 10'000 + kLastSeenResolutionS);
    CHECK_FALSE(db->touch_user("1", "stale", 10'000 + 5 * kLastSeenResolutionS));
    CHECK(db->user_by_discord_id("1")->last_seen_at == 10'000 + kLastSeenResolutionS);
}

TEST_CASE("db: users_inactive_before is strict and includes broken links") {
    TempDb t;
    auto db = t.open();
    auto a = make_user("1", "h1");
    a.last_seen_at = 99;
    auto b = make_user("2", "h2");
    b.last_seen_at = 100;
    auto c = make_user("3", "h3");
    c.last_seen_at = 50;
    c.link_broken = true;
    db->upsert_user(a);
    db->upsert_user(b);
    db->upsert_user(c);
    auto got = db->users_inactive_before(100);
    REQUIRE(got.size() == 2);
    CHECK(got[0].discord_id == "3");
    CHECK(got[1].discord_id == "1");
}

TEST_CASE("db: delete_inactive_user needs the same key and a last_seen_at still before the cutoff") {
    TempDb t;
    auto db = t.open();
    auto u = make_user("1", "h1");
    u.last_seen_at = 50;
    db->upsert_user(u);
    CHECK(db->add_vote("T", "S", "1", 10) == 1);
    CHECK_FALSE(db->delete_inactive_user("1", "stale", 100));
    CHECK_FALSE(db->delete_inactive_user("1", "h1", 50));
    CHECK(db->delete_inactive_user("1", "h1", 51));
    CHECK_FALSE(db->user_by_discord_id("1"));
    CHECK(db->add_vote("T", "S", "2", 11) == 1);
}

TEST_CASE("db: migrating a version 1 database keeps its users and marks them seen now") {
    TempDb t;
    {
        sqlite3* raw = nullptr;
        REQUIRE(sqlite3_open(t.path.string().c_str(), &raw) == SQLITE_OK);
        REQUIRE(sqlite3_exec(raw,
                             "CREATE TABLE users ("
                             " discord_id TEXT PRIMARY KEY,"
                             " username TEXT NOT NULL,"
                             " key_hash TEXT NOT NULL UNIQUE,"
                             " access_sealed BLOB NOT NULL,"
                             " refresh_sealed BLOB NOT NULL,"
                             " access_expires_at INTEGER NOT NULL,"
                             " link_broken INTEGER NOT NULL DEFAULT 0);"
                             "CREATE INDEX users_expires ON users(access_expires_at);"
                             "CREATE TABLE published_icons (title_id TEXT PRIMARY KEY,"
                             " sha256 TEXT NOT NULL, published_at INTEGER NOT NULL);"
                             "CREATE TABLE votes (title_id TEXT NOT NULL, sha256 TEXT NOT NULL,"
                             " discord_id TEXT NOT NULL, created_at INTEGER NOT NULL,"
                             " PRIMARY KEY (title_id, sha256, discord_id));"
                             "CREATE INDEX votes_created ON votes(created_at);"
                             "CREATE TABLE blocked_hashes (sha256 TEXT PRIMARY KEY);"
                             "INSERT INTO users VALUES ('1', 'old', 'h1', x'01', x'02', 1000, 1);"
                             "PRAGMA user_version = 1;",
                             nullptr, nullptr, nullptr) == SQLITE_OK);
        sqlite3_close(raw);
    }
    const int64_t before = static_cast<int64_t>(std::time(nullptr));
    auto db = t.open();
    const int64_t after = static_cast<int64_t>(std::time(nullptr));
    auto u = db->user_by_key_hash("h1");
    REQUIRE(u);
    CHECK(u->username == "old");
    CHECK(u->link_broken);
    CHECK(u->last_seen_at >= before);
    CHECK(u->last_seen_at <= after);
    CHECK(db->users_inactive_before(before).empty());
    db.reset();
    // Reopening a migrated database runs no migration again.
    auto again = t.open();
    CHECK(again->user_by_key_hash("h1")->last_seen_at == u->last_seen_at);
}

TEST_CASE("db: migrating a version 2 database keeps its users with no avatar") {
    TempDb t;
    {
        sqlite3* raw = nullptr;
        REQUIRE(sqlite3_open(t.path.string().c_str(), &raw) == SQLITE_OK);
        REQUIRE(sqlite3_exec(raw,
                             "CREATE TABLE users ("
                             " discord_id TEXT PRIMARY KEY,"
                             " username TEXT NOT NULL,"
                             " key_hash TEXT NOT NULL UNIQUE,"
                             " access_sealed BLOB NOT NULL,"
                             " refresh_sealed BLOB NOT NULL,"
                             " access_expires_at INTEGER NOT NULL,"
                             " link_broken INTEGER NOT NULL DEFAULT 0,"
                             " last_seen_at INTEGER NOT NULL DEFAULT 0);"
                             "CREATE INDEX users_expires ON users(access_expires_at);"
                             "CREATE INDEX users_last_seen ON users(last_seen_at);"
                             "CREATE TABLE published_icons (title_id TEXT PRIMARY KEY,"
                             " sha256 TEXT NOT NULL, published_at INTEGER NOT NULL);"
                             "CREATE TABLE votes (title_id TEXT NOT NULL, sha256 TEXT NOT NULL,"
                             " discord_id TEXT NOT NULL, created_at INTEGER NOT NULL,"
                             " PRIMARY KEY (title_id, sha256, discord_id));"
                             "CREATE INDEX votes_created ON votes(created_at);"
                             "CREATE TABLE blocked_hashes (sha256 TEXT PRIMARY KEY);"
                             "INSERT INTO users VALUES ('1', 'old', 'h1', x'01', x'02', 1000, 0, 777);"
                             "PRAGMA user_version = 2;",
                             nullptr, nullptr, nullptr) == SQLITE_OK);
        sqlite3_close(raw);
    }
    auto db = t.open();
    auto u = db->user_by_key_hash("h1");
    REQUIRE(u);
    CHECK(u->username == "old");
    CHECK(u->last_seen_at == 777);
    CHECK_FALSE(u->avatar);
    db.reset();
    sqlite3* raw = nullptr;
    REQUIRE(sqlite3_open(t.path.string().c_str(), &raw) == SQLITE_OK);
    int version = -1;
    REQUIRE(sqlite3_exec(
                raw, "PRAGMA user_version",
                [](void* out, int, char** vals, char**) {
                    *static_cast<int*>(out) = std::stoi(vals[0]);
                    return 0;
                },
                &version, nullptr) == SQLITE_OK);
    sqlite3_close(raw);
    CHECK(version == 3);
}

TEST_CASE("db: update_identity stores username and avatar, and null clears it") {
    TempDb t;
    auto db = t.open();
    db->upsert_user(make_user("1", "h1"));
    CHECK_FALSE(db->user_by_discord_id("1")->avatar);

    CHECK(db->update_identity("1", "h1", "alice2", std::string("0123456789abcdef0123456789abcdef")));
    auto got = db->user_by_discord_id("1");
    REQUIRE(got);
    CHECK(got->username == "alice2");
    CHECK(got->avatar == std::optional<std::string>("0123456789abcdef0123456789abcdef"));

    CHECK(db->update_identity("1", "h1", "alice3", std::nullopt));
    got = db->user_by_discord_id("1");
    CHECK(got->username == "alice3");
    CHECK_FALSE(got->avatar);

    CHECK(db->update_identity("1", "h1", "alice3", std::string("aa")));
    CHECK_FALSE(db->update_identity("1", "stale", "evil", std::nullopt));
    CHECK_FALSE(db->update_identity("2", "h1", "evil", std::nullopt));
    got = db->user_by_discord_id("1");
    CHECK(got->username == "alice3");
    CHECK(got->avatar == std::optional<std::string>("aa"));
}
