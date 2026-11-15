#include <doctest/doctest.h>

#include <string>

#include "rate_limit.hpp"

using namespace relay;

namespace {
constexpr int64_t kHourMs = 3'600'000;
}

TEST_CASE("rate limit: allows capacity requests then refuses with a retry delay") {
    int64_t now = 1'000'000;
    RateLimiter rl(10, kHourMs, [&] { return now; });
    for (int i = 0; i < 10; ++i) CHECK_FALSE(rl.take("a"));
    auto retry = rl.take("a");
    REQUIRE(retry);
    CHECK(*retry == 360);
}

TEST_CASE("rate limit: one token comes back per window / capacity") {
    int64_t now = 0;
    RateLimiter rl(10, kHourMs, [&] { return now; });
    for (int i = 0; i < 10; ++i) REQUIRE_FALSE(rl.take("a"));
    now += 359'999;
    auto retry = rl.take("a");
    REQUIRE(retry);
    CHECK(*retry == 1);
    now += 1;
    CHECK_FALSE(rl.take("a"));
    CHECK(rl.take("a"));
}

TEST_CASE("rate limit: a full window refills the whole bucket, never more") {
    int64_t now = 0;
    RateLimiter rl(3, 60'000, [&] { return now; });
    for (int i = 0; i < 3; ++i) REQUIRE_FALSE(rl.take("a"));
    REQUIRE(rl.take("a"));
    now += 10 * 60'000;
    for (int i = 0; i < 3; ++i) CHECK_FALSE(rl.take("a"));
    CHECK(rl.take("a"));
}

TEST_CASE("rate limit: keys are independent") {
    int64_t now = 0;
    RateLimiter rl(2, 60'000, [&] { return now; });
    CHECK_FALSE(rl.take("a"));
    CHECK_FALSE(rl.take("a"));
    CHECK(rl.take("a"));
    CHECK_FALSE(rl.take("b"));
    CHECK_FALSE(rl.take("b"));
    CHECK(rl.take("b"));
}

TEST_CASE("rate limit: idle keys are pruned once their bucket is full again") {
    int64_t now = 0;
    RateLimiter rl(5, 60'000, [&] { return now; });
    for (int i = 0; i < 100; ++i) rl.take("k" + std::to_string(i));
    CHECK(rl.size() == 100);
    now += 30'000;
    rl.take("fresh");
    CHECK(rl.size() == 101);
    now += 60'000;
    rl.take("fresh");
    CHECK(rl.size() == 1);
}

TEST_CASE("rate limit: a pruned key starts with a full bucket") {
    int64_t now = 0;
    RateLimiter rl(1, 60'000, [&] { return now; });
    CHECK_FALSE(rl.take("a"));
    CHECK(rl.take("a"));
    now += 60'000;
    rl.take("other");
    CHECK_FALSE(rl.take("a"));
    CHECK(rl.take("a"));
}

TEST_CASE("rate limit: a full table refuses new keys but keeps serving known ones") {
    int64_t now = 0;
    RateLimiter rl(5, 60'000, [&] { return now; }, 3);
    CHECK_FALSE(rl.take("a"));
    CHECK_FALSE(rl.take("b"));
    CHECK_FALSE(rl.take("c"));
    auto refused = rl.take("d");
    REQUIRE(refused);
    CHECK(*refused >= 1);
    CHECK(rl.size() == 3);
    CHECK_FALSE(rl.take("a"));

    now = 1000;
    auto later = rl.take("e");
    REQUIRE(later);
    CHECK(*later == 59);
    CHECK(rl.size() == 3);

    now = 60'000;
    CHECK_FALSE(rl.take("d"));
    CHECK_FALSE(rl.take("e"));
}
