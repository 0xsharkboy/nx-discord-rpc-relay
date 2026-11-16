// SPDX-License-Identifier: AGPL-3.0-or-later
#include "rate_limit.hpp"

#include <algorithm>
#include <limits>
#include <utility>

namespace relay {

namespace {
int64_t to_retry_s(int64_t wait_ms) { return std::max<int64_t>((wait_ms + 999) / 1000, 1); }
}  // namespace

// Credit is counted in token-milliseconds: one token is worth window_ms credit and the bucket
// gains capacity credit per millisecond, so refill stays exact in integer arithmetic.
RateLimiter::RateLimiter(int capacity, int64_t window_ms, std::function<int64_t()> now_ms, size_t max_keys)
    : capacity_(std::max(capacity, 1)),
      window_ms_(std::max<int64_t>(window_ms, 1)),
      max_credit_(capacity_ * window_ms_),
      now_ms_(std::move(now_ms)),
      max_keys_(std::max<size_t>(max_keys, 1)) {}

std::optional<int64_t> RateLimiter::take(const std::string& key) {
    const int64_t now = now_ms_();
    std::lock_guard lk(mu_);
    if (!last_prune_ms_) last_prune_ms_ = now;
    if (now - *last_prune_ms_ >= window_ms_) prune_locked(now);

    auto it = buckets_.find(key);
    if (it == buckets_.end()) {
        // Sweeping is O(n), so a flood of new keys triggers at most one sweep per second.
        if (buckets_.size() >= max_keys_ && now - *last_prune_ms_ >= 1000) prune_locked(now);
        if (buckets_.size() >= max_keys_) return to_retry_s(next_prunable_ms_ - now);
        it = buckets_.emplace(key, Bucket{max_credit_, now}).first;
    }
    Bucket& b = it->second;
    const int64_t elapsed = std::max<int64_t>(now - b.last_ms, 0);
    b.credit = elapsed >= window_ms_ ? max_credit_ : std::min(max_credit_, b.credit + elapsed * capacity_);
    b.last_ms = now;
    if (b.credit >= window_ms_) {
        b.credit -= window_ms_;
        return std::nullopt;
    }
    return to_retry_s((window_ms_ - b.credit + capacity_ - 1) / capacity_);
}

size_t RateLimiter::size() {
    std::lock_guard lk(mu_);
    return buckets_.size();
}

// A bucket idle for a whole window is full again, which is the same as having no entry.
void RateLimiter::prune_locked(int64_t now) {
    last_prune_ms_ = now;
    int64_t oldest = std::numeric_limits<int64_t>::max();
    std::erase_if(buckets_, [&](const auto& kv) {
        if (now - kv.second.last_ms >= window_ms_) return true;
        oldest = std::min(oldest, kv.second.last_ms);
        return false;
    });
    next_prunable_ms_ = oldest == std::numeric_limits<int64_t>::max() ? now : oldest + window_ms_;
}

}  // namespace relay
