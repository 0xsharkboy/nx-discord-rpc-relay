// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>

namespace relay {

struct ActivitySpec {
    std::string name, details, large_image, large_text;
    // The badge: empty when the presence does not show it.
    std::string small_image, small_text, small_url;
    std::optional<int64_t> start_unix_s;
    bool operator==(const ActivitySpec&) const = default;
};

// Every call happens on the SDK thread.
class IPresenceBackend {
public:
    virtual ~IPresenceBackend() = default;
    virtual void connect(const std::string& discord_id, const std::string& access_token) = 0;
    virtual void set(const std::string& discord_id, const ActivitySpec&) = 0;
    virtual void clear(const std::string& discord_id) = 0;
    virtual void disconnect(const std::string& discord_id) = 0;
    virtual void update_token(const std::string& discord_id, const std::string& access_token) = 0;
    virtual void run_callbacks() = 0;

    // Invoked from run_callbacks when a client's connection ends without disconnect() being called.
    std::function<void(const std::string& discord_id, bool auth_failed)> on_connection_lost;
};

}  // namespace relay
