#pragma once

#include <deque>
#include <mutex>
#include <optional>
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
        return pop(poll_results, poll_default);
    }
    RefreshResult refresh(const std::string& refresh_token) override {
        std::lock_guard lk(mu_);
        ++refresh_calls;
        refreshed_tokens.push_back(refresh_token);
        return pop(refresh_results, refresh_default);
    }
    void revoke(const std::string& token) override {
        std::lock_guard lk(mu_);
        revoked.push_back(token);
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
