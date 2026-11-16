// SPDX-License-Identifier: AGPL-3.0-or-later
#include <doctest/doctest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <future>
#include <thread>
#include <unistd.h>

#include "crypto.hpp"
#include "fake_oauth.hpp"
#include "links.hpp"

using namespace relay;
using namespace std::chrono_literals;

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

TEST_CASE("links: linking stores the avatar and the poll returns discord_id and avatar") {
    Fixture f;
    const std::string hash = "0123456789abcdef0123456789abcdef";
    auto id = f.started();
    f.oauth.poll_results.push_back(FakeOAuth::granted("42", "alice", "access-1", "refresh-1", 604800, hash));
    auto p = f.links->poll(id);
    CHECK(p.state == LinkPoll::Linked);
    CHECK(p.discord_id == "42");
    CHECK(p.avatar == std::optional<std::string>(hash));
    auto u = f.db->user_by_key_hash(sha256_hex(p.api_key));
    REQUIRE(u);
    CHECK(u->avatar == std::optional<std::string>(hash));
    // A repeated poll within the keep window carries them too.
    auto again = f.links->poll(id);
    CHECK(again.discord_id == "42");
    CHECK(again.avatar == std::optional<std::string>(hash));

    auto id2 = f.started();
    f.oauth.poll_results.push_back(FakeOAuth::granted("43", "bob"));
    auto p2 = f.links->poll(id2);
    CHECK(p2.discord_id == "43");
    CHECK_FALSE(p2.avatar);
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
    CHECK(f.links->unlink("42", sha256_hex(p.api_key)));
    // The key dies at once; the Discord calls wait for the background flush.
    CHECK(f.oauth.revoked.empty());
    CHECK_FALSE(f.db->user_by_discord_id("42"));
    CHECK_FALSE(f.db->user_by_key_hash(sha256_hex(p.api_key)));
    f.links->flush_revocations();
    CHECK(f.oauth.revoked == std::vector<std::string>{"access-1", "refresh-1"});
    f.links->flush_revocations();
    CHECK(f.oauth.revoked.size() == 2);
}

TEST_CASE("links: unlink with a stale key hash revokes nothing") {
    Fixture f;
    auto id = f.started();
    f.oauth.poll_results.push_back(FakeOAuth::granted());
    auto p = f.links->poll(id);
    CHECK_FALSE(f.links->unlink("42", "stale"));
    f.links->flush_revocations();
    CHECK(f.oauth.revoked.empty());
    CHECK(f.db->user_by_key_hash(sha256_hex(p.api_key)));
}

TEST_CASE("links: unlink skips tokens that fail to decrypt and ignores unknown users") {
    Fixture f;
    CHECK_FALSE(f.links->unlink("nobody", "h"));
    f.links->flush_revocations();
    CHECK(f.oauth.revoked.empty());
    User u;
    u.discord_id = "9";
    u.username = "bob";
    u.key_hash = "h";
    u.access_sealed = {1, 2, 3};
    u.refresh_sealed = seal(f.key, "refresh-9");
    f.db->upsert_user(u);
    CHECK(f.links->unlink("9", "h"));
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
    auto p = f.links->poll(id);
    f.links->unlink("42", sha256_hex(p.api_key));
    f.oauth.throw_on_revoke_token = "access-1";
    CHECK_NOTHROW(f.links->flush_revocations());
    CHECK(f.oauth.revoked == std::vector<std::string>{"access-1", "refresh-1"});
}

namespace {
// Releases a blocked fake on every exit path so a failing check cannot hang the worker join.
struct Gate {
    std::promise<void> promise;
    std::shared_future<void> future = promise.get_future().share();
    bool opened = false;
    void open() {
        if (!opened) promise.set_value();
        opened = true;
    }
    ~Gate() { open(); }
};

void link_and_unlink(Fixture& f) {
    auto id = f.started();
    f.oauth.poll_results.push_back(FakeOAuth::granted());
    auto p = f.links->poll(id);
    REQUIRE(f.links->unlink("42", sha256_hex(p.api_key)));
}
}  // namespace

TEST_CASE("links: the revocation worker sends queued revocations") {
    Fixture f;
    link_and_unlink(f);
    std::atomic<int> calls{0};
    f.oauth.during_revoke = [&](const std::string&) { ++calls; };
    auto worker = std::async(std::launch::async, [&] { f.links->run_revocations(10ms); });
    const auto until = std::chrono::steady_clock::now() + 2s;
    while (calls < 2 && std::chrono::steady_clock::now() < until) std::this_thread::sleep_for(1ms);
    f.links->stop_revocations();
    REQUIRE(worker.wait_for(2s) == std::future_status::ready);
    CHECK(f.oauth.revoked == std::vector<std::string>{"access-1", "refresh-1"});
}

TEST_CASE("links: stopping wakes an idle revocation worker at once") {
    Fixture f;
    auto worker = std::async(std::launch::async, [&] { f.links->run_revocations(1h); });
    std::this_thread::sleep_for(20ms);
    const auto start = std::chrono::steady_clock::now();
    f.links->stop_revocations();
    REQUIRE(worker.wait_for(2s) == std::future_status::ready);
    CHECK(std::chrono::steady_clock::now() - start < 500ms);
}

TEST_CASE("links: stopping drops queued revocations and waits only for the one in flight") {
    Fixture f;
    link_and_unlink(f);
    Gate entered, release;
    f.oauth.during_revoke = [&](const std::string& token) {
        if (token != "access-1") return;
        entered.open();
        release.future.wait();
    };
    auto worker = std::async(std::launch::async, [&] { f.links->run_revocations(10ms); });
    REQUIRE(entered.future.wait_for(2s) == std::future_status::ready);
    f.links->stop_revocations();
    release.open();
    const auto start = std::chrono::steady_clock::now();
    REQUIRE(worker.wait_for(2s) == std::future_status::ready);
    CHECK(std::chrono::steady_clock::now() - start < 500ms);
    CHECK(f.oauth.revoked == std::vector<std::string>{"access-1"});
    f.links->flush_revocations();
    CHECK(f.oauth.revoked == std::vector<std::string>{"access-1"});
}

TEST_CASE("links: linking marks the account as seen at link time") {
    Fixture f;
    auto id = f.started();
    f.oauth.poll_results.push_back(FakeOAuth::granted());
    f.links->poll(id);
    CHECK(f.db->user_by_discord_id("42")->last_seen_at == f.now / 1000);
}

TEST_CASE("links: relinking does not revoke the replaced tokens") {
    // Discord revokes every token of the application for a user when any one is revoked, so
    // revoking the replaced pair would also kill the new link.
    Fixture f;
    auto id1 = f.started();
    f.oauth.poll_results.push_back(FakeOAuth::granted());
    f.links->poll(id1);
    auto id2 = f.started();
    f.oauth.poll_results.push_back(FakeOAuth::granted("42", "alice", "access-2", "refresh-2"));
    REQUIRE(f.links->poll(id2).state == LinkPoll::Linked);
    f.links->flush_revocations();
    CHECK(f.oauth.revoked.empty());
}

namespace {
std::string link_as(Fixture& f, const std::string& discord_id) {
    auto id = f.started();
    f.oauth.poll_results.push_back(
        FakeOAuth::granted(discord_id, "u" + discord_id, "access-" + discord_id, "refresh-" + discord_id));
    auto p = f.links->poll(id);
    REQUIRE(p.state == LinkPoll::Linked);
    return sha256_hex(p.api_key);
}
}  // namespace

TEST_CASE("links: the inactivity sweep removes accounts unseen for 90 days and queues their revocation") {
    Fixture f;
    const int64_t day_ms = 86'400'000;
    auto stale_hash = link_as(f, "1");
    f.db->add_vote("T", "S", "1", f.now / 1000);
    f.now += 2 * day_ms;
    auto fresh_hash = link_as(f, "2");
    auto broken_hash = link_as(f, "3");
    f.db->break_link("3", broken_hash);
    // "1" was last seen 91 days ago, "2" and "3" 89 days ago.
    f.now += 89 * day_ms;
    CHECK(kInactiveAccountLifetimeS == 90 * 86400);
    auto removed = f.links->expire_inactive();
    CHECK(removed == std::vector<std::string>{"1"});
    CHECK_FALSE(f.db->user_by_key_hash(stale_hash));
    CHECK(f.db->user_by_key_hash(fresh_hash));
    CHECK(f.db->user_by_key_hash(broken_hash));
    CHECK(f.db->add_vote("T", "S", "9", f.now / 1000) == 1);
    CHECK(f.oauth.revoked.empty());
    f.links->flush_revocations();
    CHECK(f.oauth.revoked == std::vector<std::string>{"access-1", "refresh-1"});

    // A broken link follows the same rule.
    f.now += 2 * day_ms;
    removed = f.links->expire_inactive();
    std::sort(removed.begin(), removed.end());
    CHECK(removed == std::vector<std::string>{"2", "3"});
    CHECK_FALSE(f.db->user_by_key_hash(broken_hash));
}

TEST_CASE("links: the inactivity sweep keeps an account seen again after the snapshot") {
    Fixture f;
    const int64_t day_ms = 86'400'000;
    auto hash = link_as(f, "1");
    f.now += 91 * day_ms;
    // Seen right now: the sweep must not delete it.
    REQUIRE(f.db->touch_user("1", hash, f.now / 1000));
    CHECK(f.links->expire_inactive().empty());
    CHECK(f.db->user_by_key_hash(hash));
}

TEST_CASE("links: linking again drops that account's revocations still queued") {
    Fixture f;
    auto hash = link_as(f, "1");
    auto other = link_as(f, "2");
    REQUIRE(f.links->unlink("1", hash));
    REQUIRE(f.links->unlink("2", other));
    // "1" links again before the flush: revoking its old tokens would kill the new grant.
    f.oauth.poll_results.push_back(FakeOAuth::granted("1", "u1", "access-new", "refresh-new"));
    auto id = f.started();
    REQUIRE(f.links->poll(id).state == LinkPoll::Linked);
    f.links->flush_revocations();
    CHECK(f.oauth.revoked == std::vector<std::string>{"access-2", "refresh-2"});
}

TEST_CASE("links: linking again after the inactivity sweep drops its queued revocations") {
    Fixture f;
    link_as(f, "1");
    f.now += 91 * 86'400'000LL;
    REQUIRE(f.links->expire_inactive() == std::vector<std::string>{"1"});
    link_as(f, "1");
    f.links->flush_revocations();
    CHECK(f.oauth.revoked.empty());
}

TEST_CASE("links: a link during a flush drops that account's revocations not yet sent") {
    Fixture f;
    auto a = link_as(f, "1");
    auto b = link_as(f, "2");
    REQUIRE(f.links->unlink("2", b));
    REQUIRE(f.links->unlink("1", a));
    bool relinked = false;
    f.oauth.during_revoke = [&](const std::string& token) {
        if (token != "access-2" || relinked) return;
        relinked = true;
        link_as(f, "1");
    };
    f.links->flush_revocations();
    CHECK(relinked);
    CHECK(f.oauth.revoked == std::vector<std::string>{"access-2", "refresh-2"});
}
