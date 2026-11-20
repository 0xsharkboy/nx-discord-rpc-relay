// SPDX-License-Identifier: AGPL-3.0-or-later
#include "refusals.hpp"

#include <algorithm>
#include <utility>
#include <vector>

namespace relay {

void RefusalCounts::refused(std::string_view code) {
    std::lock_guard lk(mu_);
    auto it = by_code_.find(code);
    if (it != by_code_.end()) {
        ++it->second;
    } else if (by_code_.size() < kMaxCodes) {
        by_code_.emplace(std::string(code), 1);
    } else {
        ++other_;
    }
}

std::string RefusalCounts::drain_line() {
    std::lock_guard lk(mu_);
    std::vector<std::pair<std::string, uint64_t>> sorted(by_code_.begin(), by_code_.end());
    // Most frequent first, then by code, so the line is stable.
    std::stable_sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) { return a.second > b.second; });
    std::string line = "relay: refused requests in the last 24 h:";
    for (const auto& [code, n] : sorted) line += ' ' + code + '=' + std::to_string(n);
    if (other_ != 0) line += " other=" + std::to_string(other_);
    if (sorted.empty() && other_ == 0) line += " none";
    by_code_.clear();
    other_ = 0;
    return line;
}

}  // namespace relay
