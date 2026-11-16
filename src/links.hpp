// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <array>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "db.hpp"
#include "oauth.hpp"

namespace relay {

// An account with no accepted PUT /v1/presence for this long is deleted by expire_inactive().
constexpr int64_t kInactiveAccountLifetimeS = 90 * 86400;

struct LinkStart {
    std::string link_id, user_code, verification_uri_complete;
    int expires_in = 0, interval = 5;
};

struct LinkPoll {
    // Unknown: never issued or already purged.
    enum State { Pending, Expired, Denied, Linked, Error, Unknown } state = Pending;
    std::string api_key, username, discord_id;
    std::optional<std::string> avatar;
};

class Links {
public:
    Links(IOAuth& oauth, Db& db, const std::array<uint8_t, 32>& token_key,
          std::function<int64_t()> now_ms);

    std::optional<LinkStart> start();
    LinkPoll poll(const std::string& link_id);
    // Deletes the user at once (the key dies with it) and queues the Discord revocations, so the
    // request never waits on Discord.
    // Returns whether the account still held `key_hash` and was unlinked.
    bool unlink(const std::string& discord_id, const std::string& key_hash);
    // Deletes every account, broken links included, not seen for kInactiveAccountLifetimeS, and
    // queues its revocations like unlink. Returns the discord ids removed.
    std::vector<std::string> expire_inactive();
    // Sends the queued revocations, best effort. Once stopped, drops whatever is left unsent.
    // A link drops the revocations still queued for its account: Discord revokes every token of the
    // application for a user when any one is revoked, so sending them would kill the new grant.
    void flush_revocations();
    // Flushes every `every` until stop_revocations(). Runs on its own thread.
    void run_revocations(std::chrono::milliseconds every);
    // Shutdown: queued revocations are dropped and only one already in flight is waited for.
    void stop_revocations();

    std::function<void(const std::string& discord_id)> on_relinked;

private:
    struct Entry {
        std::string device_code;
        int64_t interval_ms = 5000;
        int64_t expires_at_ms = 0;
        int64_t last_poll_ms = 0;
        int64_t linked_at_ms = 0;
        bool polling = false;
        LinkPoll::State state = LinkPoll::Pending;
        std::string api_key, username, discord_id;
        std::optional<std::string> avatar;
    };

    void purge_locked(int64_t now);
    LinkPoll finish_grant(const std::string& link_id, const Tokens& t, int64_t now);
    void queue_revocations_locked(const User&);

    IOAuth& oauth_;
    Db& db_;
    std::array<uint8_t, 32> key_;
    std::function<int64_t()> now_ms_;
    std::mutex mu_;
    std::unordered_map<std::string, Entry> entries_;
    std::mutex revoke_mu_;
    struct Revocation {
        std::string discord_id, token;
    };
    // Taken one at a time, so a link can still drop the entries of its account that are not sent yet.
    std::deque<Revocation> pending_revocations_;
    std::condition_variable revoke_cv_;
    bool revoke_stop_ = false;
};

}  // namespace relay
