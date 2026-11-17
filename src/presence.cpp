// SPDX-License-Identifier: AGPL-3.0-or-later
#include "presence.hpp"

#include <cstdlib>
#include <exception>
#include <iostream>
#include <utility>

#include "crypto.hpp"
#include "icons.hpp"

namespace relay {

namespace {

constexpr int64_t kMinSendIntervalMs = 5000;
constexpr int64_t kIdleClearMs = 150000;
constexpr int64_t kDisconnectAfterClearMs = 60000;
constexpr int64_t kReconnectIntervalMs = 30000;
constexpr int64_t kStartJitterS = 2;

// Heartbeats recompute the start from a fresh elapsed value, so it drifts by a second or so.
bool same_activity(const ActivitySpec& a, const std::optional<ActivitySpec>& b) {
    if (!b) return false;
    if (a.name != b->name || a.details != b->details || a.large_image != b->large_image ||
        a.large_text != b->large_text)
        return false;
    if (a.start_unix_s.has_value() != b->start_unix_s.has_value()) return false;
    return !a.start_unix_s || std::llabs(*a.start_unix_s - *b->start_unix_s) < kStartJitterS;
}

}  // namespace

Presence::Presence(IPresenceBackend& backend, Db& db, const std::array<uint8_t, 32>& token_key, ImageFor image_for,
                   std::function<int64_t()> now_ms)
    : backend_(backend),
      db_(db),
      key_(token_key),
      image_for_(std::move(image_for)),
      now_ms_(std::move(now_ms)) {
    backend_.on_connection_lost = [this](const std::string& id, bool auth_failed) {
        connection_lost(id, auth_failed);
    };
}

Presence::~Presence() { backend_.on_connection_lost = nullptr; }

void Presence::put(const std::string& discord_id, const PresenceUpdate& update) {
    enqueue({Command::Put, discord_id, update, now_ms_()});
}

void Presence::clear(const std::string& discord_id) { enqueue({Command::Clear, discord_id, {}, 0}); }

void Presence::drop(const std::string& discord_id) { enqueue({Command::Drop, discord_id, {}, 0}); }

void Presence::attach_icon(const std::string& discord_id, const std::string& title_id, const std::string& sha256) {
    PresenceUpdate u;
    u.title_id = title_id;
    u.icon = sha256;
    enqueue({Command::Attach, discord_id, std::move(u), 0});
}

void Presence::icons_changed() { enqueue({Command::IconsChanged, {}, {}, 0}); }

std::unordered_set<std::string> Presence::icons_in_use() {
    std::lock_guard lk(icons_mu_);
    return icons_in_use_;
}

void Presence::token_refreshed(const std::string& discord_id) {
    enqueue({Command::Token, discord_id, {}, 0});
}

std::optional<ActivitySpec> Presence::current(const std::string& discord_id) {
    std::lock_guard lk(snapshot_mu_);
    auto it = snapshot_.find(discord_id);
    if (it == snapshot_.end()) return std::nullopt;
    return it->second;
}

void Presence::enqueue(Command c) {
    std::lock_guard lk(queue_mu_);
    queue_.push_back(std::move(c));
}

void Presence::tick() {
    const int64_t now = now_ms_();
    std::vector<Command> commands;
    {
        std::lock_guard lk(queue_mu_);
        commands.swap(queue_);
    }
    // The queue is already swapped out: one failing command must not lose the ones behind it.
    for (const auto& c : commands) {
        try {
            apply(c, now);
        } catch (const std::exception& e) {
            std::cerr << "relay: presence command for " << c.key << " failed: " << e.what() << '\n';
        }
    }
    for (auto it = states_.begin(); it != states_.end();) {
        if (step(it->first, it->second, now)) {
            ++it;
        } else {
            publish(it->first, std::nullopt);
            if (it->second.icon) icons_dirty_ = true;
            it = states_.erase(it);
        }
    }
    // Last, so that connection_lost never runs while states_ is being iterated.
    backend_.run_callbacks();
    sync_icons();
}

void Presence::clear_all() {
    {
        std::lock_guard lk(queue_mu_);
        queue_.clear();
    }
    const int64_t now = now_ms_();
    for (auto& [id, st] : states_)
        if (!st.cleared_at_ms) clear_user(id, st, now);
}

void Presence::disconnect_all() {
    for (auto& [id, st] : states_)
        if (st.connected) backend_.disconnect(id);
    states_.clear();
    icons_dirty_ = true;
    sync_icons();
    std::lock_guard lk(snapshot_mu_);
    snapshot_.clear();
}

void Presence::apply(const Command& c, int64_t now) {
    switch (c.kind) {
    case Command::Put: {
        auto& st = states_[c.key];
        const auto& u = c.update;
        std::optional<std::string> tid;
        if (u.title_id && valid_title_id(*u.title_id)) tid = normalize_title_id(*u.title_id);
        // A v0.3 console never sends the hash: the one attached by its upload stays while the
        // title does.
        std::optional<std::string> icon = st.icon;
        if (u.icon && Icons::valid_sha256(*u.icon)) icon = u.icon;
        else if (tid != st.title_id) icon.reset();
        if (icon != st.icon) icons_dirty_ = true;
        st.title_id = std::move(tid);
        st.icon = std::move(icon);
        ActivitySpec spec;
        spec.name = u.name;
        spec.details = u.details;
        spec.large_image = image_for(st);
        spec.large_text = u.name;
        if (u.elapsed_s) spec.start_unix_s = c.at_ms / 1000 - *u.elapsed_s;
        st.desired = std::move(spec);
        st.last_seen_ms = c.at_ms;
        st.cleared_at_ms.reset();
        break;
    }
    case Command::Clear: {
        auto it = states_.find(c.key);
        if (it != states_.end() && !it->second.cleared_at_ms) clear_user(c.key, it->second, now);
        break;
    }
    case Command::Drop: {
        auto it = states_.find(c.key);
        if (it == states_.end()) break;
        if (it->second.connected) {
            if (it->second.sent) backend_.clear(c.key);
            backend_.disconnect(c.key);
        }
        forget(c.key);
        break;
    }
    case Command::Attach: {
        // An upload that arrives after the title changed only stores the file.
        auto it = states_.find(c.key);
        const auto& u = c.update;
        if (it == states_.end() || !u.title_id || !valid_title_id(*u.title_id) || !u.icon ||
            !Icons::valid_sha256(*u.icon))
            break;
        auto& st = it->second;
        if (st.title_id != normalize_title_id(*u.title_id)) break;
        if (st.icon != u.icon) icons_dirty_ = true;
        st.icon = u.icon;
        if (st.desired) st.desired->large_image = image_for(st);
        break;
    }
    case Command::IconsChanged: {
        for (auto& [id, st] : states_)
            if (st.desired) st.desired->large_image = image_for(st);
        break;
    }
    case Command::Token: {
        auto it = states_.find(c.key);
        if (it == states_.end() || !it->second.connected) break;
        auto t = access_token(c.key, now);
        if (t.state == TokenLookup::Ready) backend_.update_token(c.key, t.token);
        break;
    }
    }
}

bool Presence::step(const std::string& id, UserState& st, int64_t now) {
    if (!st.cleared_at_ms && now - st.last_seen_ms >= kIdleClearMs) clear_user(id, st, now);
    if (st.cleared_at_ms) {
        if (!st.connected) return false;
        if (now - *st.cleared_at_ms < kDisconnectAfterClearMs) return true;
        backend_.disconnect(id);
        return false;
    }
    if (!st.desired) return true;
    if (!st.connected) {
        if (st.last_connect_ms && now - *st.last_connect_ms < kReconnectIntervalMs) return true;
        auto t = access_token(id, now);
        if (t.state == TokenLookup::Gone) return false;
        if (t.state == TokenLookup::Later) {
            st.last_connect_ms = now;
            return true;
        }
        backend_.connect(id, t.token);
        st.connected = true;
        st.key_hash = std::move(t.key_hash);
        st.last_connect_ms = now;
    }
    if (same_activity(*st.desired, st.sent)) return true;
    if (st.last_sent_ms && now - *st.last_sent_ms < kMinSendIntervalMs) return true;
    backend_.set(id, *st.desired);
    st.sent = st.desired;
    st.last_sent_ms = now;
    publish(id, st.sent);
    return true;
}

// A clear is applied immediately (not held by the 5 s limit) but counts as a change, so a put
// right after it waits for the limit.
void Presence::clear_user(const std::string& id, UserState& st, int64_t now) {
    if (st.connected && st.sent) {
        backend_.clear(id);
        st.last_sent_ms = now;
    }
    st.desired.reset();
    st.sent.reset();
    st.cleared_at_ms = now;
    publish(id, std::nullopt);
}

void Presence::forget(const std::string& id) {
    if (states_.erase(id) != 0) icons_dirty_ = true;
    publish(id, std::nullopt);
}

void Presence::connection_lost(const std::string& id, bool auth_failed) {
    auto it = states_.find(id);
    if (it == states_.end() || !it->second.connected) return;
    backend_.disconnect(id);
    if (auth_failed) {
        try {
            db_.break_link(id, it->second.key_hash);
        } catch (const std::exception& e) {
            std::cerr << "relay: presence could not mark " << id << " as link broken: " << e.what() << '\n';
        }
        forget(id);
        return;
    }
    it->second.connected = false;
    it->second.sent.reset();
    publish(id, std::nullopt);
}

// An expired access token is not a broken link: the refresher will store a fresh one, and
// connecting with the stale one would end in an auth failure that marks the link broken.
Presence::TokenLookup Presence::access_token(const std::string& id, int64_t now) {
    std::optional<User> user;
    try {
        user = db_.reader().user_by_discord_id(id);
    } catch (const std::exception& e) {
        std::cerr << "relay: presence could not load user " << id << ": " << e.what() << '\n';
        return {TokenLookup::Later, {}, {}};
    }
    if (!user || user->link_broken) return {TokenLookup::Gone, {}, {}};
    if (user->access_expires_at <= now / 1000) return {TokenLookup::Later, {}, {}};
    auto token = open(key_, user->access_sealed);
    if (!token) return {TokenLookup::Gone, {}, {}};
    return {TokenLookup::Ready, std::move(*token), std::move(user->key_hash)};
}

std::string Presence::image_for(const UserState& st) {
    try {
        return image_for_(st.title_id, st.icon);
    } catch (const std::exception& e) {
        std::cerr << "relay: presence could not look up an icon: " << e.what() << '\n';
    }
    return "switch_logo";
}

void Presence::sync_icons() {
    if (!icons_dirty_) return;
    std::unordered_set<std::string> in_use;
    for (const auto& [id, st] : states_)
        if (st.icon) in_use.insert(*st.icon);
    std::lock_guard lk(icons_mu_);
    icons_in_use_.swap(in_use);
    icons_dirty_ = false;
}

void Presence::publish(const std::string& id, const std::optional<ActivitySpec>& spec) {
    std::lock_guard lk(snapshot_mu_);
    if (spec)
        snapshot_[id] = *spec;
    else
        snapshot_.erase(id);
}

}  // namespace relay
