#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "db.hpp"
#include "oauth.hpp"

namespace relay {

struct LinkStart {
    std::string link_id, user_code, verification_uri_complete;
    int expires_in = 0, interval = 5;
};

struct LinkPoll {
    // Unknown: never issued or already purged.
    enum State { Pending, Expired, Denied, Linked, Error, Unknown } state = Pending;
    std::string api_key, username;
};

class Links {
public:
    Links(IOAuth& oauth, Db& db, const std::array<uint8_t, 32>& token_key,
          std::function<int64_t()> now_ms);

    std::optional<LinkStart> start();
    LinkPoll poll(const std::string& link_id);
    // Deletes the user at once (the key dies with it) and queues the Discord revocations, so the
    // request never waits on Discord.
    void unlink(const std::string& discord_id);
    // Sends the queued revocations, best effort. Called from the background jobs thread.
    void flush_revocations();

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
        std::string api_key, username;
    };

    void purge_locked(int64_t now);
    LinkPoll finish_grant(const std::string& link_id, const Tokens& t, int64_t now);

    IOAuth& oauth_;
    Db& db_;
    std::array<uint8_t, 32> key_;
    std::function<int64_t()> now_ms_;
    std::mutex mu_;
    std::unordered_map<std::string, Entry> entries_;
    std::mutex revoke_mu_;
    std::vector<std::string> pending_revocations_;
};

}  // namespace relay
