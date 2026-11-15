#include <doctest/doctest.h>

#include <atomic>
#include <filesystem>
#include <stdexcept>
#include <unistd.h>
#include <string>

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
    db->delete_user("1");
    CHECK_FALSE(db->user_by_discord_id("1"));
    CHECK_FALSE(db->user_by_key_hash("h1"));
    db->delete_user("1");
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
    db->update_tokens("1", a, r, 4242);
    auto u = db->user_by_discord_id("1");
    REQUIRE(u);
    CHECK(u->access_sealed == a);
    CHECK(u->refresh_sealed == r);
    CHECK(u->access_expires_at == 4242);
    CHECK(u->key_hash == "h1");
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
    REQUIRE_NOTHROW(db->update_tokens("2", std::span<const uint8_t>{}, std::span<const uint8_t>{}, 7));
    auto two = db->user_by_discord_id("2");
    REQUIRE(two);
    CHECK(two->access_sealed.empty());
    CHECK(two->refresh_sealed.empty());
    CHECK(two->access_expires_at == 7);
    CHECK_FALSE(db->user_by_key_hash(std::string_view{}));
    CHECK_FALSE(db->is_blocked(std::string_view{}));
}
