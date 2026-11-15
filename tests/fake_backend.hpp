#pragma once

#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "presence_backend.hpp"

namespace relay {

class FakeBackend : public IPresenceBackend {
public:
    enum class Kind { Connect, Set, Clear, Disconnect, UpdateToken };
    struct Call {
        Kind kind;
        std::string discord_id;
        std::string token;
        std::optional<ActivitySpec> spec;
    };

    void connect(const std::string& id, const std::string& token) override {
        record({Kind::Connect, id, token, std::nullopt});
    }
    void set(const std::string& id, const ActivitySpec& spec) override { record({Kind::Set, id, {}, spec}); }
    void clear(const std::string& id) override { record({Kind::Clear, id, {}, std::nullopt}); }
    void disconnect(const std::string& id) override { record({Kind::Disconnect, id, {}, std::nullopt}); }
    void update_token(const std::string& id, const std::string& token) override {
        record({Kind::UpdateToken, id, token, std::nullopt});
    }
    void run_callbacks() override {
        std::lock_guard lk(mu_);
        ++run_callbacks_count_;
    }

    // Simulates the SDK reporting a lost connection, as run_callbacks would.
    void lose(const std::string& id, bool auth_failed) {
        if (on_connection_lost) on_connection_lost(id, auth_failed);
    }

    std::vector<Call> calls() {
        std::lock_guard lk(mu_);
        return calls_;
    }
    std::vector<Call> calls(Kind kind) {
        std::lock_guard lk(mu_);
        std::vector<Call> out;
        for (const auto& c : calls_)
            if (c.kind == kind) out.push_back(c);
        return out;
    }
    std::vector<Call> calls(Kind kind, const std::string& id) {
        auto all = calls(kind);
        std::erase_if(all, [&](const Call& c) { return c.discord_id != id; });
        return all;
    }
    void reset() {
        std::lock_guard lk(mu_);
        calls_.clear();
    }
    int run_callbacks_count() {
        std::lock_guard lk(mu_);
        return run_callbacks_count_;
    }

private:
    void record(Call c) {
        std::lock_guard lk(mu_);
        calls_.push_back(std::move(c));
    }
    std::mutex mu_;
    std::vector<Call> calls_;
    int run_callbacks_count_ = 0;
};

}  // namespace relay
