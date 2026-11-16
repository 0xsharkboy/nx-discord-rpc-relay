#pragma once

#include <array>
#include <cstdint>
#include <functional>

#include "db.hpp"
#include "oauth.hpp"
#include "presence.hpp"

namespace relay {

class Refresher {
public:
    // `now_s` returns unix seconds.
    Refresher(IOAuth& oauth, Db& db, const std::array<uint8_t, 32>& token_key, Presence& presence,
              std::function<int64_t()> now_s);

    // Never throws; a failure for one user does not stop the others. Once `stopping` returns true,
    // the run ends after the user in progress.
    void run_once(const std::function<bool()>& stopping = {});

private:
    // False when Discord refused the relay's client credentials, which ends the run.
    bool refresh_user(const User& u, int64_t now);
    void break_link(const User& u);

    IOAuth& oauth_;
    Db& db_;
    std::array<uint8_t, 32> key_;
    Presence& presence_;
    std::function<int64_t()> now_s_;
};

}  // namespace relay
