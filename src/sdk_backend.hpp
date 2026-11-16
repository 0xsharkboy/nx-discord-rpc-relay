// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "presence_backend.hpp"

namespace discordpp {
class Client;
}

namespace relay {

// One discordpp::Client per user. Not thread-safe: everything, including the destructor, runs on
// the SDK thread.
class SdkBackend : public IPresenceBackend {
public:
    explicit SdkBackend(uint64_t application_id);
    ~SdkBackend() override;
    SdkBackend(const SdkBackend&) = delete;
    SdkBackend& operator=(const SdkBackend&) = delete;

    void connect(const std::string& discord_id, const std::string& access_token) override;
    void set(const std::string& discord_id, const ActivitySpec&) override;
    void clear(const std::string& discord_id) override;
    void disconnect(const std::string& discord_id) override;
    void update_token(const std::string& discord_id, const std::string& access_token) override;
    void run_callbacks() override;

private:
    struct Entry {
        std::shared_ptr<discordpp::Client> client;
        bool ready = false;
        bool started = false;
        bool applied = false;
        std::optional<ActivitySpec> latest;
    };
    struct Retiring {
        std::chrono::steady_clock::time_point until;
        std::shared_ptr<discordpp::Client> client;
    };

    Entry* active(const std::string& id, const discordpp::Client* client);
    void lost(const std::string& id, bool auth_failed);
    void apply(const std::string& id, Entry& e);
    void retire(std::shared_ptr<discordpp::Client> client);

    uint64_t application_id_;
    std::unordered_map<std::string, Entry> clients_;
    std::vector<Retiring> retiring_;
};

}  // namespace relay
