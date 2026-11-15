#include <doctest/doctest.h>

#include <atomic>
#include <filesystem>
#include <unistd.h>

#include "crypto.hpp"
#include "fake_oauth.hpp"
#include "links.hpp"

using namespace relay;

namespace {
struct Fixture {
    std::filesystem::path path;
    std::unique_ptr<Db> db;
    FakeOAuth oauth;
    std::array<uint8_t, 32> key{};
    int64_t now = 1'000'000'000'000;
    std::unique_ptr<Links> links;
    std::vector<std::string> relinked;

    Fixture() {
        static std::atomic<int> n{0};
        path = std::filesystem::temp_directory_path() /
               ("relay_links_test_" + std::to_string(::getpid()) + "_" + std::to_string(n++) + ".db");
        db = Db::open(path.string());
        key.fill(7);
        links = std::make_unique<Links>(oauth, *db, key, [this] { return now; });
        links->on_relinked = [this](const std::string& id) { relinked.push_back(id); };
    }
    ~Fixture() {
        links.reset();
        db.reset();
        for (const char* s : {"", "-wal", "-shm"}) std::filesystem::remove(path.string() + s);
    }
    // Starts a link and moves the clock past the first interval.
    std::string started() {
        auto s = links->start();
        REQUIRE(s);
        now += 5000;
        return s->link_id;
    }
};
}  // namespace

TEST_CASE("links: start returns a 22 char link_id and device fields") {
    Fixture f;
    auto s = f.links->start();
    REQUIRE(s);
    CHECK(s->link_id.size() == 22);
    CHECK(s->user_code == "ABCD-EFGH");
    CHECK(s->expires_in == 300);
    CHECK(s->interval == 5);
}

TEST_CASE("links: start fails when device_authorize fails") {
    Fixture f;
    f.oauth.device_result.reset();
    CHECK_FALSE(f.links->start());
}

TEST_CASE("links: unknown id") {
    Fixture f;
    CHECK(f.links->poll("nope").state == LinkPoll::Unknown);
}

TEST_CASE("links: poll respects the interval") {
    Fixture f;
    auto s = f.links->start();
    REQUIRE(s);
    CHECK(f.links->poll(s->link_id).state == LinkPoll::Pending);
    CHECK(f.oauth.poll_calls == 0);
    f.now += 4999;
    CHECK(f.links->poll(s->link_id).state == LinkPoll::Pending);
    CHECK(f.oauth.poll_calls == 0);
    f.now += 1;
    CHECK(f.links->poll(s->link_id).state == LinkPoll::Pending);
    CHECK(f.oauth.poll_calls == 1);
    CHECK(f.oauth.polled_codes[0] == "device-code-secret");
    CHECK(f.links->poll(s->link_id).state == LinkPoll::Pending);
    CHECK(f.oauth.poll_calls == 1);
}

TEST_CASE("links: slow_down adds 5 seconds") {
    Fixture f;
    auto id = f.started();
    f.oauth.poll_results.push_back(FakeOAuth::state(PollState::SlowDown));
    CHECK(f.links->poll(id).state == LinkPoll::Pending);
    f.now += 5000;
    CHECK(f.links->poll(id).state == LinkPoll::Pending);
    CHECK(f.oauth.poll_calls == 1);
    f.now += 5000;
    f.links->poll(id);
    CHECK(f.oauth.poll_calls == 2);
}

TEST_CASE("links: granted yields a key, a user row and sealed tokens") {
    Fixture f;
    auto id = f.started();
    f.oauth.poll_results.push_back(FakeOAuth::granted());
    auto p = f.links->poll(id);
    CHECK(p.state == LinkPoll::Linked);
    CHECK(p.api_key.size() == 43);
    CHECK(p.username == "alice");
    auto u = f.db->user_by_key_hash(sha256_hex(p.api_key));
    REQUIRE(u);
    CHECK(u->discord_id == "42");
    CHECK(u->username == "alice");
    CHECK_FALSE(u->link_broken);
    CHECK(u->access_expires_at == f.now / 1000 + 604800);
    CHECK(open(f.key, u->access_sealed) == std::optional<std::string>("access-1"));
    CHECK(open(f.key, u->refresh_sealed) == std::optional<std::string>("refresh-1"));
    CHECK(f.relinked.empty());
}

TEST_CASE("links: a repeated poll within 60 s returns the same key") {
    Fixture f;
    auto id = f.started();
    f.oauth.poll_results.push_back(FakeOAuth::granted());
    auto a = f.links->poll(id);
    f.now += 30'000;
    auto b = f.links->poll(id);
    CHECK(b.state == LinkPoll::Linked);
    CHECK(b.api_key == a.api_key);
    CHECK(b.username == "alice");
    CHECK(f.oauth.poll_calls == 1);
    CHECK(f.db->user_by_discord_id("42")->key_hash == sha256_hex(a.api_key));
}

TEST_CASE("links: 61 s after linking the poll returns expired, then unknown after purge") {
    Fixture f;
    auto id = f.started();
    f.oauth.poll_results.push_back(FakeOAuth::granted());
    f.links->poll(id);
    f.now += 61'000;
    auto p = f.links->poll(id);
    CHECK(p.state == LinkPoll::Expired);
    CHECK(p.api_key.empty());
    f.now += 400'000;
    CHECK(f.links->poll(id).state == LinkPoll::Expired);
    CHECK(f.links->poll(id).state == LinkPoll::Unknown);
}

TEST_CASE("links: relinking replaces the key and fires on_relinked") {
    Fixture f;
    auto id1 = f.started();
    f.oauth.poll_results.push_back(FakeOAuth::granted());
    auto first = f.links->poll(id1);
    CHECK(f.relinked.empty());

    auto id2 = f.started();
    f.oauth.poll_results.push_back(FakeOAuth::granted("42", "alice2", "access-2", "refresh-2"));
    auto second = f.links->poll(id2);
    CHECK(second.state == LinkPoll::Linked);
    CHECK(second.api_key != first.api_key);
    CHECK_FALSE(f.db->user_by_key_hash(sha256_hex(first.api_key)));
    CHECK(f.db->user_by_key_hash(sha256_hex(second.api_key)));
    CHECK(f.relinked == std::vector<std::string>{"42"});
    CHECK(f.db->user_by_discord_id("42")->username == "alice2");
}

TEST_CASE("links: relinking clears link_broken") {
    Fixture f;
    auto id1 = f.started();
    f.oauth.poll_results.push_back(FakeOAuth::granted());
    f.links->poll(id1);
    f.db->set_link_broken("42", true);
    auto id2 = f.started();
    f.oauth.poll_results.push_back(FakeOAuth::granted());
    f.links->poll(id2);
    CHECK_FALSE(f.db->user_by_discord_id("42")->link_broken);
}

TEST_CASE("links: oauth expired and denied are sticky") {
    Fixture f;
    auto a = f.started();
    f.oauth.poll_results.push_back(FakeOAuth::state(PollState::Expired));
    CHECK(f.links->poll(a).state == LinkPoll::Expired);
    f.now += 5000;
    CHECK(f.links->poll(a).state == LinkPoll::Expired);
    CHECK(f.oauth.poll_calls == 1);

    auto b = f.started();
    f.oauth.poll_results.push_back(FakeOAuth::state(PollState::Denied));
    CHECK(f.links->poll(b).state == LinkPoll::Denied);
    f.now += 5000;
    CHECK(f.links->poll(b).state == LinkPoll::Denied);
    CHECK(f.oauth.poll_calls == 2);
}

TEST_CASE("links: oauth error is transient") {
    Fixture f;
    auto id = f.started();
    f.oauth.poll_results.push_back(FakeOAuth::state(PollState::Error));
    CHECK(f.links->poll(id).state == LinkPoll::Error);
    CHECK(f.links->poll(id).state == LinkPoll::Pending);
    f.now += 5000;
    f.oauth.poll_results.push_back(FakeOAuth::granted());
    CHECK(f.links->poll(id).state == LinkPoll::Linked);
}

TEST_CASE("links: pending past expiry returns expired without calling oauth") {
    Fixture f;
    auto id = f.started();
    f.now += 300'000;
    CHECK(f.links->poll(id).state == LinkPoll::Expired);
    CHECK(f.oauth.poll_calls == 0);
}

TEST_CASE("links: unlink revokes both tokens and deletes the row") {
    Fixture f;
    auto id = f.started();
    f.oauth.poll_results.push_back(FakeOAuth::granted());
    auto p = f.links->poll(id);
    f.links->unlink("42");
    // The key dies at once; the Discord calls wait for the background flush.
    CHECK(f.oauth.revoked.empty());
    CHECK_FALSE(f.db->user_by_discord_id("42"));
    CHECK_FALSE(f.db->user_by_key_hash(sha256_hex(p.api_key)));
    f.links->flush_revocations();
    CHECK(f.oauth.revoked == std::vector<std::string>{"access-1", "refresh-1"});
    f.links->flush_revocations();
    CHECK(f.oauth.revoked.size() == 2);
}

TEST_CASE("links: unlink skips tokens that fail to decrypt and ignores unknown users") {
    Fixture f;
    f.links->unlink("nobody");
    f.links->flush_revocations();
    CHECK(f.oauth.revoked.empty());
    User u;
    u.discord_id = "9";
    u.username = "bob";
    u.key_hash = "h";
    u.access_sealed = {1, 2, 3};
    u.refresh_sealed = seal(f.key, "refresh-9");
    f.db->upsert_user(u);
    f.links->unlink("9");
    f.links->flush_revocations();
    CHECK(f.oauth.revoked == std::vector<std::string>{"refresh-9"});
    CHECK_FALSE(f.db->user_by_discord_id("9"));
}

TEST_CASE("links: a throwing on_relinked does not lose the new key") {
    Fixture f;
    auto id1 = f.started();
    f.oauth.poll_results.push_back(FakeOAuth::granted());
    f.links->poll(id1);
    f.links->on_relinked = [](const std::string&) { throw std::runtime_error("boom"); };
    auto id2 = f.started();
    f.oauth.poll_results.push_back(FakeOAuth::granted("42", "alice", "access-2", "refresh-2"));
    auto p = f.links->poll(id2);
    CHECK(p.state == LinkPoll::Linked);
    CHECK(f.db->user_by_key_hash(sha256_hex(p.api_key)));
    CHECK(f.links->poll(id2).api_key == p.api_key);
}

TEST_CASE("links: an oauth exception leaves the entry able to expire and be purged") {
    Fixture f;
    auto id = f.started();
    f.oauth.throw_on_poll = true;
    CHECK_THROWS(f.links->poll(id));
    f.oauth.throw_on_poll = false;
    f.now += 5000;
    f.oauth.poll_results.push_back(FakeOAuth::state(PollState::Pending));
    CHECK(f.links->poll(id).state == LinkPoll::Pending);
    CHECK(f.oauth.poll_calls == 2);
    f.now += 400'000;
    CHECK(f.links->poll(id).state == LinkPoll::Expired);
    CHECK(f.links->poll(id).state == LinkPoll::Unknown);
}

TEST_CASE("links: a failing revoke does not stop the others") {
    Fixture f;
    auto id = f.started();
    f.oauth.poll_results.push_back(FakeOAuth::granted());
    f.links->poll(id);
    f.links->unlink("42");
    f.oauth.throw_on_revoke_token = "access-1";
    CHECK_NOTHROW(f.links->flush_revocations());
    CHECK(f.oauth.revoked == std::vector<std::string>{"access-1", "refresh-1"});
}
