// SPDX-License-Identifier: AGPL-3.0-or-later
#include "refresher.hpp"

#include <cstdio>
#include <exception>
#include <unordered_set>

#include "crypto.hpp"

namespace relay {

namespace {
constexpr int64_t kWindowS = 24 * 60 * 60;
}

Refresher::Refresher(IOAuth& oauth, Db& db, const std::array<uint8_t, 32>& token_key, Presence& presence,
                     std::function<int64_t()> now_s)
    : oauth_(oauth), db_(db), key_(token_key), presence_(presence), now_s_(std::move(now_s)) {}

void Refresher::run_once(const std::function<bool()>& stopping) {
    try {
        const int64_t now = now_s_();
        std::unordered_set<std::string> handled;
        for (const User& u : db_.users_expiring_before(now + kWindowS)) {
            if (stopping && stopping()) return;
            handled.insert(u.discord_id);
            try {
                if (!refresh_user(u, now)) {
                    // Every other user would be refused the same way.
                    std::fprintf(stderr, "refresher: refresh rejected: client credentials invalid, check "
                                         "DISCORD_CLIENT_ID and DISCORD_CLIENT_SECRET\n");
                    return;
                }
            } catch (const std::exception& e) {
                std::fprintf(stderr, "refresher: user %s failed: %s\n", u.discord_id.c_str(), e.what());
            }
        }
        backfill_identities(handled, stopping);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "refresher: run failed: %s\n", e.what());
    }
}

bool Refresher::refresh_user(const User& u, int64_t now) {
    const auto refresh_token = open(key_, u.refresh_sealed);
    if (!refresh_token) {
        break_link(u);
        return true;
    }
    const RefreshResult r = oauth_.refresh(*refresh_token);
    switch (r.state) {
    case RefreshResult::State::Refreshed: {
        if (!r.tokens) return true;
        const auto access = seal(key_, r.tokens->access_token);
        const auto refresh = seal(key_, r.tokens->refresh_token);
        if (db_.update_tokens(u.discord_id, u.key_hash, access, refresh, now + r.tokens->expires_in)) {
            presence_.token_refreshed(u.discord_id);
            refresh_identity(u, r.tokens->access_token);
        }
        break;
    }
    case RefreshResult::State::Revoked:
        break_link(u);
        break;
    case RefreshResult::State::Transient:
        break;
    case RefreshResult::State::ClientError:
        return false;
    }
    return true;
}

// Best effort: the tokens are already stored, so a failure here only leaves the old name and avatar.
void Refresher::refresh_identity(const User& u, const std::string& access_token) {
    try {
        const auto identity = oauth_.identity(access_token);
        if (!identity || identity->discord_id != u.discord_id) return;
        db_.update_identity(u.discord_id, u.key_hash,
                            identity->username.empty() ? u.username : identity->username, identity->avatar);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "refresher: identity of user %s failed: %s\n", u.discord_id.c_str(), e.what());
    }
}

// Accounts linked before avatars existed: read their identity once with the stored access token.
// Users the refresh loop handled this run are skipped, their refresh re-reads the identity. A failure
// leaves the user unchecked for the next pass.
void Refresher::backfill_identities(const std::unordered_set<std::string>& handled,
                                    const std::function<bool()>& stopping) {
    for (const User& u : db_.users_identity_unchecked()) {
        if (stopping && stopping()) return;
        if (handled.contains(u.discord_id)) continue;
        const auto access_token = open(key_, u.access_sealed);
        if (!access_token) continue;
        refresh_identity(u, *access_token);
    }
}

// A relink during the Discord call replaced the key: the new link is not ours to break.
void Refresher::break_link(const User& u) {
    if (db_.break_link(u.discord_id, u.key_hash)) presence_.drop(u.discord_id);
}

}  // namespace relay
