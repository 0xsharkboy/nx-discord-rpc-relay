// SPDX-License-Identifier: AGPL-3.0-or-later
#include "client_version.hpp"

#include <charconv>

namespace relay {

namespace {

constexpr std::string_view kAgentPrefix = "nx-discord-rpc/";
constexpr std::string_view kLinePrefix = "relay: client versions in the last 24 h:";

// Leading digits of `s` into `out`; advances `s`. No sign, no empty part, no overflow.
bool take_part(std::string_view& s, uint32_t& out) {
    if (s.empty() || s.front() < '0' || s.front() > '9') return false;
    auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), out);
    if (ec != std::errc{}) return false;
    s.remove_prefix(static_cast<size_t>(p - s.data()));
    return true;
}

bool take_dot(std::string_view& s) {
    if (s.empty() || s.front() != '.') return false;
    s.remove_prefix(1);
    return true;
}

}  // namespace

std::optional<Version> parse_version(std::string_view s) {
    Version v;
    if (!take_part(s, v.major) || !take_dot(s) || !take_part(s, v.minor) || !take_dot(s) ||
        !take_part(s, v.patch) || !s.empty())
        return std::nullopt;
    return v;
}

std::optional<Version> parse_client_user_agent(std::string_view user_agent) {
    if (!user_agent.starts_with(kAgentPrefix)) return std::nullopt;
    return parse_version(user_agent.substr(kAgentPrefix.size()));
}

bool older(const Version& a, const Version& b) { return a < b; }

std::string to_string(const Version& v) {
    return std::to_string(v.major) + '.' + std::to_string(v.minor) + '.' + std::to_string(v.patch);
}

void VersionCounts::seen(const Version& version, std::string_view key_hash) {
    std::lock_guard lk(mu_);
    auto it = by_version_.find(version);
    if (it == by_version_.end()) {
        if (by_version_.size() >= kMaxVersions) {
            other_.emplace(key_hash);
            return;
        }
        it = by_version_.emplace(version, std::set<std::string, std::less<>>{}).first;
    }
    it->second.emplace(key_hash);
}

void VersionCounts::seen_other(std::string_view key_hash) {
    std::lock_guard lk(mu_);
    other_.emplace(key_hash);
}

std::string VersionCounts::drain_line() {
    std::lock_guard lk(mu_);
    std::string line(kLinePrefix);
    // Built from the parsed numbers only, never from header text.
    for (const auto& [version, keys] : by_version_) line += ' ' + to_string(version) + '=' + std::to_string(keys.size());
    if (!other_.empty()) line += " other=" + std::to_string(other_.size());
    if (by_version_.empty() && other_.empty()) line += " none";
    by_version_.clear();
    other_.clear();
    return line;
}

}  // namespace relay
