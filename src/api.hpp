// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <cstdint>
#include <functional>
#include <string>

#include <httplib.h>

#include "client_version.hpp"
#include "config.hpp"
#include "db.hpp"
#include "icons.hpp"
#include "links.hpp"
#include "presence.hpp"
#include "rate_limit.hpp"

namespace relay {

struct Deps {
    const Config& config;
    Db& db;
    Icons& icons;
    Links& links;
    Presence& presence;
    RateLimiter& link_limiter;  // POST /v1/link, per client IP
    RateLimiter& poll_limiter;  // POST /v1/link/{id}/poll, per client IP
    RateLimiter& icon_limiter;  // PUT /v1/icons, per user key hash
    // New icon files stored by PUT /v1/icons, per user key hash; in memory only.
    RateLimiter& new_icon_limiter;
    std::function<int64_t()> monotonic_ms;  // request durations in the log
    std::function<void(const std::string& line)> log;
    std::function<int64_t()> unix_s;  // last_seen_at; defaults to the system clock
    // Distinct keys per console version for the daily log line; nullptr counts nothing.
    VersionCounts* version_counts = nullptr;
};

constexpr size_t kMaxPayloadBytes = 262144;
constexpr size_t kMaxPresenceBodyBytes = 4096;

// Deps must outlive the server.
void register_routes(httplib::Server& svr, Deps& deps);

}  // namespace relay
