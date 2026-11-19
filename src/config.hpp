// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

#include "client_version.hpp"

namespace relay {

inline constexpr std::string_view kDefaultBadgeUrl = "https://github.com/0xsharkboy/nx-discord-rpc";

struct Config {
    std::string client_id, client_secret, public_base_url, listen_host, data_dir;
    std::array<uint8_t, 32> token_key{};
    std::optional<std::string> admin_key;
    // Consoles older than this get 426 on /v1/; unset refuses nobody.
    std::optional<Version> min_client_version;
    // Opened by a click on the badge.
    std::string badge_url = std::string(kDefaultBadgeUrl);
    int listen_port = 8080;
    bool trust_proxy = false;
};

// Returns the Config, or an error message that never includes a variable's value.
std::variant<Config, std::string> load_config(
    const std::function<std::optional<std::string>(const char*)>& getenv);

}  // namespace relay
