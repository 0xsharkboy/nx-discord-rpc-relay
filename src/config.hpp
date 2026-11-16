// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <variant>

namespace relay {

struct Config {
    std::string client_id, client_secret, public_base_url, listen_host, data_dir;
    std::array<uint8_t, 32> token_key{};
    std::optional<std::string> admin_key;
    int listen_port = 8080, publish_threshold = 2;
    bool trust_proxy = false;
};

// Returns the Config, or an error message that never includes a variable's value.
std::variant<Config, std::string> load_config(
    const std::function<std::optional<std::string>(const char*)>& getenv);

}  // namespace relay
