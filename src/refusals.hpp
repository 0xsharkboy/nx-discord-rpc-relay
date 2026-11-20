// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <string_view>

namespace relay {

// Refused requests per error code since the last drain, in memory only, for the daily log line.
// Codes are the relay's own fixed strings, never request data.
class RefusalCounts {
public:
    // Distinct codes kept per window; any further code counts as other.
    static constexpr size_t kMaxCodes = 64;

    void refused(std::string_view code);
    // "relay: refused requests in the last 24 h: client_outdated=12 invalid_body=3", most frequent
    // first, or "... none"; then clears the counts.
    std::string drain_line();

private:
    std::mutex mu_;
    std::map<std::string, uint64_t, std::less<>> by_code_;
    uint64_t other_ = 0;
};

}  // namespace relay
