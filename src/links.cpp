#include "links.hpp"

#include <utility>

#include "crypto.hpp"

namespace relay {

namespace {
constexpr int64_t kLinkedKeepMs = 60'000;
constexpr int64_t kSlowDownMs = 5'000;
}  // namespace

Links::Links(IOAuth& oauth, Db& db, const std::array<uint8_t, 32>& token_key,
             std::function<int64_t()> now_ms)
    : oauth_(oauth), db_(db), key_(token_key), now_ms_(std::move(now_ms)) {}

void Links::purge_locked(int64_t now) {
    for (auto it = entries_.begin(); it != entries_.end();) {
        const Entry& e = it->second;
        bool device_expired = now >= e.expires_at_ms;
        bool linked_done = e.linked_at_ms == 0 || now - e.linked_at_ms >= kLinkedKeepMs;
        if (!e.polling && device_expired && linked_done)
            it = entries_.erase(it);
        else
            ++it;
    }
}

std::optional<LinkStart> Links::start() {
    auto auth = oauth_.device_authorize();
    if (!auth) return std::nullopt;

    int64_t now = now_ms_();
    LinkStart out{random_token(16), auth->user_code, auth->verification_uri_complete,
                  auth->expires_in, auth->interval};

    Entry e;
    e.device_code = std::move(auth->device_code);
    e.interval_ms = int64_t{auth->interval} * 1000;
    e.expires_at_ms = now + int64_t{auth->expires_in} * 1000;
    e.last_poll_ms = now;

    std::lock_guard lk(mu_);
    purge_locked(now);
    entries_.emplace(out.link_id, std::move(e));
    return out;
}

LinkPoll Links::poll(const std::string& link_id) {
    int64_t now = now_ms_();
    std::string device_code;
    {
        std::lock_guard lk(mu_);
        auto it = entries_.find(link_id);
        if (it == entries_.end()) {
            purge_locked(now);
            return {LinkPoll::Unknown, {}, {}};
        }
        Entry& e = it->second;

        auto answer = [&]() -> std::optional<LinkPoll> {
            if (e.state == LinkPoll::Linked) {
                if (now - e.linked_at_ms < kLinkedKeepMs) return LinkPoll{LinkPoll::Linked, e.api_key, e.username};
                e.api_key.clear();
                e.username.clear();
                e.state = LinkPoll::Expired;
            }
            if (e.state == LinkPoll::Expired || e.state == LinkPoll::Denied) return LinkPoll{e.state, {}, {}};
            if (now >= e.expires_at_ms) {
                e.state = LinkPoll::Expired;
                return LinkPoll{LinkPoll::Expired, {}, {}};
            }
            if (e.polling || now - e.last_poll_ms < e.interval_ms) return LinkPoll{LinkPoll::Pending, {}, {}};
            return std::nullopt;
        }();
        if (answer) {
            purge_locked(now);
            return *answer;
        }
        e.polling = true;
        e.last_poll_ms = now;
        device_code = e.device_code;
    }

    struct InFlight {
        Links& self;
        const std::string& id;
        ~InFlight() {
            std::lock_guard lk(self.mu_);
            if (auto it = self.entries_.find(id); it != self.entries_.end()) it->second.polling = false;
        }
    } in_flight{*this, link_id};

    PollResult r = oauth_.poll(device_code);

    if (r.state == PollState::Granted && r.tokens) return finish_grant(link_id, *r.tokens, now);

    std::lock_guard lk(mu_);
    LinkPoll out{LinkPoll::Pending, {}, {}};
    if (auto it = entries_.find(link_id); it != entries_.end()) {
        Entry& e = it->second;
        switch (r.state) {
            case PollState::Pending: break;
            case PollState::SlowDown: e.interval_ms += kSlowDownMs; break;
            case PollState::Expired:
                e.state = LinkPoll::Expired;
                out.state = LinkPoll::Expired;
                break;
            case PollState::Denied:
                e.state = LinkPoll::Denied;
                out.state = LinkPoll::Denied;
                break;
            default: out.state = LinkPoll::Error; break;
        }
    }
    return out;
}

LinkPoll Links::finish_grant(const std::string& link_id, const Tokens& t, int64_t now) {
    std::string api_key = random_token(32);
    bool existed = db_.user_by_discord_id(t.discord_id).has_value();

    User u;
    u.discord_id = t.discord_id;
    u.username = t.username;
    u.key_hash = sha256_hex(api_key);
    u.access_sealed = seal(key_, t.access_token);
    u.refresh_sealed = seal(key_, t.refresh_token);
    u.access_expires_at = now / 1000 + t.expires_in;
    u.link_broken = false;
    db_.upsert_user(u);

    {
        std::lock_guard lk(mu_);
        if (auto it = entries_.find(link_id); it != entries_.end()) {
            Entry& e = it->second;
            e.state = LinkPoll::Linked;
            e.api_key = api_key;
            e.username = t.username;
            e.linked_at_ms = now;
        }
    }

    // The old key is already dead and the new one is stored: a throwing hook must not lose it.
    if (existed && on_relinked) {
        try {
            on_relinked(t.discord_id);
        } catch (...) {
        }
    }
    return {LinkPoll::Linked, std::move(api_key), t.username};
}

void Links::unlink(const std::string& discord_id) {
    auto u = db_.user_by_discord_id(discord_id);
    if (!u) return;
    for (const auto* sealed : {&u->access_sealed, &u->refresh_sealed}) {
        if (auto token = open(key_, *sealed)) oauth_.revoke(*token);
    }
    db_.delete_user(discord_id);
}

}  // namespace relay
