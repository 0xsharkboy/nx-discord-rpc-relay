// SPDX-License-Identifier: AGPL-3.0-or-later
#include "config.hpp"

#include <algorithm>
#include <charconv>
#include <iostream>
#include <string_view>
#include <vector>

#include "crypto.hpp"

namespace relay {

namespace {

std::optional<int> parse_int(std::string_view s, int lo, int hi) {
    int v = 0;
    auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    if (s.empty() || ec != std::errc{} || p != s.data() + s.size() || v < lo || v > hi) return std::nullopt;
    return v;
}

}  // namespace

std::variant<Config, std::string> load_config(
    const std::function<std::optional<std::string>(const char*)>& getenv) {
    auto get = [&](const char* name) -> std::optional<std::string> {
        auto v = getenv(name);
        if (v && v->empty()) return std::nullopt;
        return v;
    };

    Config c;
    std::vector<std::string> missing;
    std::vector<std::string> invalid;

    auto required = [&](const char* name, std::string& out) {
        if (auto v = get(name)) out = *v;
        else missing.emplace_back(name);
    };
    required("DISCORD_CLIENT_ID", c.client_id);
    required("DISCORD_CLIENT_SECRET", c.client_secret);
    std::string key_b64;
    required("TOKEN_ENC_KEY", key_b64);
    required("PUBLIC_BASE_URL", c.public_base_url);

    if (!missing.empty()) {
        std::string msg = "missing required environment variables:";
        for (auto& m : missing) msg += " " + m;
        return msg;
    }

    if (!std::all_of(c.client_id.begin(), c.client_id.end(), [](char ch) { return ch >= '0' && ch <= '9'; }))
        invalid.emplace_back("DISCORD_CLIENT_ID must be a decimal number");

    auto key = base64_decode(key_b64);
    if (!key || key->size() != 32) invalid.emplace_back("TOKEN_ENC_KEY must be base64 of exactly 32 bytes");
    else std::copy(key->begin(), key->end(), c.token_key.begin());

    constexpr std::string_view https = "https://";
    if (c.public_base_url.rfind(https, 0) != 0 || c.public_base_url.size() == https.size() ||
        c.public_base_url.back() == '/')
        invalid.emplace_back("PUBLIC_BASE_URL must be an https URL without a trailing slash");

    c.listen_host = "0.0.0.0";
    if (auto addr = get("LISTEN_ADDR")) {
        auto colon = addr->rfind(':');
        std::optional<int> port;
        if (colon != std::string::npos && colon > 0)
            port = parse_int(std::string_view(*addr).substr(colon + 1), 1, 65535);
        if (!port) invalid.emplace_back("LISTEN_ADDR must be host:port with a port in 1-65535");
        else {
            c.listen_host = addr->substr(0, colon);
            c.listen_port = *port;
        }
    }

    // Icons are no longer published by vote; an old env file keeps working.
    if (getenv("PUBLISH_THRESHOLD")) std::cerr << "relay: PUBLISH_THRESHOLD is no longer used and is ignored\n";

    if (auto v = get("TRUST_PROXY")) {
        if (*v == "true" || *v == "1") c.trust_proxy = true;
        else if (*v == "false" || *v == "0") c.trust_proxy = false;
        else invalid.emplace_back("TRUST_PROXY must be true or false");
    }

    if (auto v = get("MIN_CLIENT_VERSION")) {
        c.min_client_version = parse_version(*v);
        if (!c.min_client_version) invalid.emplace_back("MIN_CLIENT_VERSION must be X.Y.Z, or empty for no minimum");
    }

    c.data_dir = get("DATA_DIR").value_or("/data");
    c.admin_key = get("ADMIN_KEY");

    if (!invalid.empty()) {
        std::string msg = "invalid configuration:";
        for (auto& m : invalid) msg += "\n  " + m;
        return msg;
    }
    return c;
}

}  // namespace relay
