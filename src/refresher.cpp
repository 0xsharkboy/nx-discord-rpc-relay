#include "refresher.hpp"

#include <cstdio>
#include <exception>

#include "crypto.hpp"

namespace relay {

namespace {
constexpr int64_t kWindowS = 24 * 60 * 60;
}

Refresher::Refresher(IOAuth& oauth, Db& db, const std::array<uint8_t, 32>& token_key, Presence& presence,
                     std::function<int64_t()> now_s)
    : oauth_(oauth), db_(db), key_(token_key), presence_(presence), now_s_(std::move(now_s)) {}

void Refresher::run_once() {
    try {
        const int64_t now = now_s_();
        for (const User& u : db_.users_expiring_before(now + kWindowS)) {
            try {
                refresh_user(u, now);
            } catch (const std::exception& e) {
                std::fprintf(stderr, "refresher: user %s failed: %s\n", u.discord_id.c_str(), e.what());
            }
        }
    } catch (const std::exception& e) {
        std::fprintf(stderr, "refresher: run failed: %s\n", e.what());
    }
}

void Refresher::refresh_user(const User& u, int64_t now) {
    const auto refresh_token = open(key_, u.refresh_sealed);
    if (!refresh_token) {
        break_link(u.discord_id);
        return;
    }
    const RefreshResult r = oauth_.refresh(*refresh_token);
    switch (r.state) {
    case RefreshResult::State::Refreshed: {
        if (!r.tokens) return;
        const auto access = seal(key_, r.tokens->access_token);
        const auto refresh = seal(key_, r.tokens->refresh_token);
        db_.update_tokens(u.discord_id, access, refresh, now + r.tokens->expires_in);
        presence_.token_refreshed(u.discord_id);
        break;
    }
    case RefreshResult::State::Revoked:
        break_link(u.discord_id);
        break;
    case RefreshResult::State::Transient:
        break;
    }
}

void Refresher::break_link(const std::string& discord_id) {
    db_.set_link_broken(discord_id, true);
    presence_.drop(discord_id);
}

}  // namespace relay
