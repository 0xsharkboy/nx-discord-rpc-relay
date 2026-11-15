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
#include "presence_backend.hpp"

namespace relay {

struct PresenceUpdate {
    std::string name, details;
    std::optional<int64_t> elapsed_s;
    std::optional<std::string> title_id;
};

// Public methods other than tick() only enqueue and are safe from any thread. tick() and every
// backend call run on the SDK thread.
class Presence {
public:
    // `now_ms` returns unix milliseconds.
    Presence(IPresenceBackend& backend, Db& db, const std::array<uint8_t, 32>& token_key,
             std::string public_base_url, std::function<bool(const std::string& tid)> icon_published,
             std::function<int64_t()> now_ms);
    ~Presence();
    Presence(const Presence&) = delete;
    Presence& operator=(const Presence&) = delete;

    void put(const std::string& discord_id, const PresenceUpdate&);
    void clear(const std::string& discord_id);
    void drop(const std::string& discord_id);
    void icon_published(const std::string& title_id);
    void token_refreshed(const std::string& discord_id);
    void tick();
    // The activity last sent to the backend; nullopt when cleared, not yet sent or unknown.
    std::optional<ActivitySpec> current(const std::string& discord_id);

    // Shutdown, on the SDK thread once no request can enqueue anymore. clear_all() discards queued
    // commands and clears every shown activity; disconnect_all() then ends every client. Pump the
    // backend in between so the clears are delivered before the connections close.
    void clear_all();
    void disconnect_all();

private:
    struct Command {
        enum Kind { Put, Clear, Drop, Icon, Token } kind;
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
        // The link the client was connected with; an auth loss may only break that one.
        std::string key_hash;
    };

    void enqueue(Command c);
    void apply(const Command& c, int64_t now);
    // False when the user must be forgotten.
    bool step(const std::string& id, UserState& st, int64_t now);
    void clear_user(const std::string& id, UserState& st, int64_t now);
    void forget(const std::string& id);
    void connection_lost(const std::string& id, bool auth_failed);
    struct TokenLookup {
        // Gone: forget the user. Later: keep the desired state and retry at the reconnect pace.
        enum State { Ready, Gone, Later } state;
        std::string token, key_hash;
    };
    TokenLookup access_token(const std::string& id, int64_t now);
    std::string image_for(const std::optional<std::string>& tid);
    void publish(const std::string& id, const std::optional<ActivitySpec>& spec);

    IPresenceBackend& backend_;
    Db& db_;
    std::array<uint8_t, 32> key_;
    std::string base_url_;
    std::function<bool(const std::string&)> icon_is_published_;
    std::function<int64_t()> now_ms_;

    std::mutex queue_mu_;
    std::vector<Command> queue_;

    std::mutex snapshot_mu_;
    std::unordered_map<std::string, ActivitySpec> snapshot_;

    std::unordered_map<std::string, UserState> states_;
};

}  // namespace relay
