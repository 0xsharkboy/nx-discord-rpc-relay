// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <compare>
#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <string_view>

namespace relay {

// A console version X.Y.Z, compared numerically: 0.10.0 is newer than 0.9.1.
struct Version {
    uint32_t major = 0, minor = 0, patch = 0;
    auto operator<=>(const Version&) const = default;
};

// Exactly X.Y.Z, each part decimal digits that fit in 32 bits; anything else is nullopt.
std::optional<Version> parse_version(std::string_view s);

// The console's User-Agent is exactly "nx-discord-rpc/X.Y.Z". Any other User-Agent, or ours with a
// version that does not parse, is nullopt: such a client is never refused.
std::optional<Version> parse_client_user_agent(std::string_view user_agent);

// True when `a` is older than `b`.
bool older(const Version& a, const Version& b);

std::string to_string(const Version& v);

// The distinct API key hashes seen per client version since the last drain, in memory only. Only
// the totals ever leave this class.
class VersionCounts {
public:
    // Distinct versions kept per window; keys seen with any further version count as other, so a
    // client cannot grow the map without bound by inventing versions.
    static constexpr size_t kMaxVersions = 64;

    void seen(const Version& version, std::string_view key_hash);
    // A keyed request whose User-Agent is not the console's, or carries no parsable version.
    void seen_other(std::string_view key_hash);
    // "relay: client versions in the last 24 h: 0.6.0=120 0.5.0=14 other=2", newest first, then
    // clears every set.
    std::string drain_line();

private:
    std::mutex mu_;
    std::map<Version, std::set<std::string, std::less<>>, std::greater<>> by_version_;
    std::set<std::string, std::less<>> other_;
};

}  // namespace relay
