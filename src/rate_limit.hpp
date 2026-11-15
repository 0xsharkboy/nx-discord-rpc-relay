#pragma once

#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace relay {

// Token bucket per key: `capacity` requests per `window_ms`, refilled continuously. Thread-safe.
class RateLimiter {
public:
    // `now_ms` must be monotonic enough that it never goes backwards by much.
    RateLimiter(int capacity, int64_t window_ms, std::function<int64_t()> now_ms);

    // nullopt when the request is allowed (and counted); otherwise the seconds to wait, at least 1.
    std::optional<int64_t> take(const std::string& key);
    size_t size();

private:
    struct Bucket {
        int64_t credit;
        int64_t last_ms;
    };
    void prune_locked(int64_t now);

    int64_t capacity_, window_ms_, max_credit_;
    std::function<int64_t()> now_ms_;
    std::mutex mu_;
    std::unordered_map<std::string, Bucket> buckets_;
    std::optional<int64_t> last_prune_ms_;
};

}  // namespace relay
