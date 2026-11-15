#include "rate_limit.hpp"

#include <algorithm>
#include <utility>

namespace relay {

// Credit is counted in token-milliseconds: one token is worth window_ms credit and the bucket
// gains capacity credit per millisecond, so refill stays exact in integer arithmetic.
RateLimiter::RateLimiter(int capacity, int64_t window_ms, std::function<int64_t()> now_ms)
    : capacity_(std::max(capacity, 1)),
      window_ms_(std::max<int64_t>(window_ms, 1)),
      max_credit_(capacity_ * window_ms_),
      now_ms_(std::move(now_ms)) {}

std::optional<int64_t> RateLimiter::take(const std::string& key) {
    const int64_t now = now_ms_();
    std::lock_guard lk(mu_);
    prune_locked(now);
    auto [it, inserted] = buckets_.try_emplace(key, Bucket{max_credit_, now});
    Bucket& b = it->second;
    if (!inserted) {
        const int64_t elapsed = std::max<int64_t>(now - b.last_ms, 0);
        b.credit = elapsed >= window_ms_ ? max_credit_ : std::min(max_credit_, b.credit + elapsed * capacity_);
        b.last_ms = now;
    }
    if (b.credit >= window_ms_) {
        b.credit -= window_ms_;
        return std::nullopt;
    }
    const int64_t wait_ms = (window_ms_ - b.credit + capacity_ - 1) / capacity_;
    return std::max<int64_t>((wait_ms + 999) / 1000, 1);
}

size_t RateLimiter::size() {
    std::lock_guard lk(mu_);
    return buckets_.size();
}

// A bucket idle for a whole window is full again, which is the same as having no entry.
void RateLimiter::prune_locked(int64_t now) {
    if (!last_prune_ms_) last_prune_ms_ = now;
    if (now - *last_prune_ms_ < window_ms_) return;
    last_prune_ms_ = now;
    std::erase_if(buckets_, [&](const auto& kv) { return now - kv.second.last_ms >= window_ms_; });
}

}  // namespace relay
