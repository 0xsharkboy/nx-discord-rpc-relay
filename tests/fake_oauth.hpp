#pragma once

#include <deque>
#include <functional>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "oauth.hpp"

namespace relay {

class FakeOAuth : public IOAuth {
public:
    std::optional<DeviceAuth> device_result = DeviceAuth{
        "device-code-secret", "ABCD-EFGH", "https://discord.com/activate?user_code=ABCD-EFGH", 300, 5};
    std::deque<PollResult> poll_results;
    PollResult poll_default{PollState::Pending, std::nullopt};
    std::deque<RefreshResult> refresh_results;
    RefreshResult refresh_default{RefreshResult::State::Transient, std::nullopt};

    bool throw_on_poll = false;
    std::string throw_on_refresh_token;
    // Runs inside refresh(), outside the fake's lock, to simulate work racing the Discord call.
    std::function<void()> during_refresh;
    std::string throw_on_revoke_token;
    // Runs inside revoke(), outside the fake's lock, to simulate a slow Discord call.
    std::function<void(const std::string&)> during_revoke;
    int authorize_calls = 0, poll_calls = 0, refresh_calls = 0;
    std::vector<std::string> polled_codes, refreshed_tokens, revoked;

    static PollResult granted(const std::string& discord_id = "42", const std::string& username = "alice",
                              const std::string& access = "access-1",
                              const std::string& refresh = "refresh-1", int64_t expires_in = 604800) {
        return {PollState::Granted, Tokens{access, refresh, expires_in, discord_id, username}};
    }
    static PollResult state(PollState s) { return {s, std::nullopt}; }

    std::optional<DeviceAuth> device_authorize() override {
        std::lock_guard lk(mu_);
        ++authorize_calls;
        return device_result;
    }
    PollResult poll(const std::string& device_code) override {
        std::lock_guard lk(mu_);
        ++poll_calls;
        polled_codes.push_back(device_code);
        if (throw_on_poll) throw std::runtime_error("poll failed");
        return pop(poll_results, poll_default);
    }
    RefreshResult refresh(const std::string& refresh_token) override {
        if (during_refresh) during_refresh();
        std::lock_guard lk(mu_);
        ++refresh_calls;
        refreshed_tokens.push_back(refresh_token);
        if (!throw_on_refresh_token.empty() && refresh_token == throw_on_refresh_token)
            throw std::runtime_error("refresh failed");
        return pop(refresh_results, refresh_default);
    }
    void revoke(const std::string& token) override {
        if (during_revoke) during_revoke(token);
        std::lock_guard lk(mu_);
        revoked.push_back(token);
        if (!throw_on_revoke_token.empty() && token == throw_on_revoke_token)
            throw std::runtime_error("revoke failed");
    }

private:
    template <class T>
    static T pop(std::deque<T>& q, const T& fallback) {
        if (q.empty()) return fallback;
        T v = std::move(q.front());
        q.pop_front();
        return v;
    }
    std::mutex mu_;
};

}  // namespace relay
