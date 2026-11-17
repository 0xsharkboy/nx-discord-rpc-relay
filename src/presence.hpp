// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "db.hpp"
#include "presence_backend.hpp"

namespace relay {

struct PresenceUpdate {
    std::string name, details;
    std::optional<int64_t> elapsed_s;
    std::optional<std::string> title_id;
    // An icon hash (64 lowercase hex) the caller has validated.
    std::optional<std::string> icon;
};

// The large image of a presence: an image URL or "switch_logo".
using ImageFor = std::function<std::string(const std::optional<std::string>& title_id,
                                           const std::optional<std::string>& icon)>;

// Public methods other than tick() only enqueue and are safe from any thread. tick() and every
// backend call run on the SDK thread.
class Presence {
public:
    // `now_ms` returns unix milliseconds.
    Presence(IPresenceBackend& backend, Db& db, const std::array<uint8_t, 32>& token_key, ImageFor image_for,
             std::function<int64_t()> now_ms);
    ~Presence();
    Presence(const Presence&) = delete;
    Presence& operator=(const Presence&) = delete;

    void put(const std::string& discord_id, const PresenceUpdate&);
    void clear(const std::string& discord_id);
    void drop(const std::string& discord_id);
    // Attaches an uploaded icon to the user's presence, only while it shows that title.
    void attach_icon(const std::string& discord_id, const std::string& title_id, const std::string& sha256);
    // Re-evaluates every user's image; call it after an icon was removed.
    void icons_changed();
    void token_refreshed(const std::string& discord_id);
    void tick();
    // The activity last sent to the backend; nullopt when cleared, not yet sent or unknown.
    std::optional<ActivitySpec> current(const std::string& discord_id);
    // The icon hashes held by the users' presences as of the last tick.
    std::unordered_set<std::string> icons_in_use();
    // Test hook: how many times tick() has stepped a user so far.
    uint64_t step_count() const { return step_count_; }

    // Shutdown, on the SDK thread once no request can enqueue anymore. clear_all() discards queued
    // commands and clears every shown activity; disconnect_all() then ends every client. Pump the
    // backend in between so the clears are delivered before the connections close.
    void clear_all();
    void disconnect_all();

private:
    struct Command {
        enum Kind { Put, Clear, Drop, Attach, IconsChanged, Token } kind;
        std::string key;
        PresenceUpdate update;
        int64_t at_ms = 0;
    };
    struct UserState {
        bool connected = false;
        std::optional<ActivitySpec> desired, sent;
        std::optional<int64_t> last_sent_ms, last_connect_ms, cleared_at_ms;
        int64_t last_seen_ms = 0;
        std::optional<std::string> title_id;
        // Kept across heartbeats of the same title, dropped when the title changes.
        std::optional<std::string> icon;
        // The link the client was connected with; an auth loss may only break that one.
        std::string key_hash;
        // When step() next has something to do without any new command; its entry in schedule_.
        std::optional<int64_t> due_ms;
    };

    void enqueue(Command c);
    void apply(const Command& c, int64_t now);
    // False when the user must be forgotten.
    bool step(const std::string& id, UserState& st, int64_t now);
    // The earliest time step() acts on its own: idle clear, disconnect after a clear, reconnect
    // or token retry, or a change held by the send limit. Mirrors the checks in step().
    static std::optional<int64_t> next_due(const UserState& st);
    void reschedule(const std::string& id, UserState& st);
    void unschedule(const std::string& id, UserState& st);
    void clear_user(const std::string& id, UserState& st, int64_t now);
    void forget(const std::string& id);
    void connection_lost(const std::string& id, bool auth_failed);
    struct TokenLookup {
        // Gone: forget the user. Later: keep the desired state and retry at the reconnect pace.
        enum State { Ready, Gone, Later } state;
        std::string token, key_hash;
    };
    TokenLookup access_token(const std::string& id, int64_t now);
    std::string image_for(const UserState& st);
    void publish(const std::string& id, const std::optional<ActivitySpec>& spec);
    // Refreshes the set icons_in_use() returns, when an icon or the set of users changed.
    void sync_icons();

    IPresenceBackend& backend_;
    Db& db_;
    std::array<uint8_t, 32> key_;
    ImageFor image_for_;
    std::function<int64_t()> now_ms_;

    std::mutex queue_mu_;
    std::vector<Command> queue_;

    std::mutex snapshot_mu_;
    std::unordered_map<std::string, ActivitySpec> snapshot_;

    // tick() steps only the users in dirty_ (touched by a command or a lost connection since their
    // last step) and those whose due time has come; idle users cost nothing. SDK thread only.
    std::unordered_map<std::string, UserState> states_;
    std::unordered_set<std::string> dirty_;
    std::set<std::pair<int64_t, std::string>> schedule_;
    bool icons_dirty_ = false;
    uint64_t step_count_ = 0;

    std::mutex icons_mu_;
    std::unordered_set<std::string> icons_in_use_;
};

}  // namespace relay
