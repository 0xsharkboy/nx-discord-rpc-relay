// SPDX-License-Identifier: AGPL-3.0-or-later
// The only translation unit that compiles the SDK's inline implementation.
#define DISCORDPP_IMPLEMENTATION
#include "discordpp.h"

#include "sdk_backend.hpp"

#include <exception>
#include <iostream>
#include <utility>

namespace relay {

namespace {

// Lets a client whose status callback is still on the stack finish before it is destroyed.
constexpr auto kRetireFor = std::chrono::seconds(5);
// Gateway close code "Authentication failed": the token was revoked or is invalid. Other close
// codes and network errors are treated as transient.
constexpr int32_t kGatewayAuthenticationFailed = 4004;

// Callbacks run inside discordpp::RunCallbacks(): an exception escaping into the SDK would
// terminate the process.
template <class F>
auto guarded(F f) {
    return [f = std::move(f)](auto&&... args) {
        try {
            f(std::forward<decltype(args)>(args)...);
        } catch (const std::exception& e) {
            std::cerr << "relay: discord callback failed: " << e.what() << '\n';
        } catch (...) {
            std::cerr << "relay: discord callback failed\n";
        }
    };
}

discordpp::Activity to_activity(const ActivitySpec& s) {
    discordpp::Activity a;
    a.SetType(discordpp::ActivityTypes::Playing);
    a.SetName(s.name);
    if (!s.details.empty()) a.SetDetails(s.details);
    if (s.start_unix_s && *s.start_unix_s > 0) {
        discordpp::ActivityTimestamps ts;
        ts.SetStart(static_cast<uint64_t>(*s.start_unix_s));
        a.SetTimestamps(ts);
    }
    discordpp::ActivityAssets assets;
    assets.SetLargeImage(s.large_image);
    assets.SetLargeText(s.large_text);
    if (!s.small_image.empty()) {
        assets.SetSmallImage(s.small_image);
        assets.SetSmallText(s.small_text);
        if (!s.small_url.empty()) assets.SetSmallUrl(s.small_url);
    }
    a.SetAssets(assets);
    return a;
}

}  // namespace

SdkBackend::SdkBackend(uint64_t application_id) : application_id_(application_id) {}

SdkBackend::~SdkBackend() {
    for (auto& [id, e] : clients_) e.client->Disconnect();
}

void SdkBackend::connect(const std::string& discord_id, const std::string& access_token) {
    if (clients_.contains(discord_id)) return;
    auto client = std::make_shared<discordpp::Client>();
    const discordpp::Client* raw = client.get();
    client->SetApplicationId(application_id_);
    client->AddLogCallback(
        guarded([discord_id](std::string message, discordpp::LoggingSeverity) {
            std::cerr << "discord sdk [" << discord_id << "]: " << message << '\n';
        }),
        discordpp::LoggingSeverity::Error);
    client->SetStatusChangedCallback(guarded([this, discord_id, raw](discordpp::Client::Status status,
                                                             discordpp::Client::Error error, int32_t detail) {
        Entry* e = active(discord_id, raw);
        if (!e) return;
        if (status == discordpp::Client::Status::Ready) {
            e->ready = true;
            e->started = true;
            apply(discord_id, *e);
            return;
        }
        e->ready = false;
        if (status != discordpp::Client::Status::Disconnected) {
            e->started = true;
            return;
        }
        if (error == discordpp::Client::Error::None && !e->started) return;
        std::cerr << "relay: discord connection for " << discord_id
                  << " ended: " << discordpp::Client::ErrorToString(error) << " (" << detail << ")\n";
        lost(discord_id,
             error == discordpp::Client::Error::UnexpectedClose && detail == kGatewayAuthenticationFailed);
    }));
    Entry entry;
    entry.client = client;
    clients_.emplace(discord_id, std::move(entry));
    try {
        client->UpdateToken(discordpp::AuthorizationTokenType::Bearer, access_token,
                            guarded([this, discord_id, raw](discordpp::ClientResult r) {
                                Entry* e = active(discord_id, raw);
                                if (!e) return;
                                if (r.Successful()) {
                                    e->client->Connect();
                                    return;
                                }
                                std::cerr << "relay: token update for " << discord_id
                                          << " failed: " << r.Error() << '\n';
                                lost(discord_id, r.Status() == discordpp::HttpStatusCode::Unauthorized);
                            }));
    } catch (...) {
        clients_.erase(discord_id);  // do not leave a client that never got a token
        throw;
    }
}

void SdkBackend::set(const std::string& discord_id, const ActivitySpec& spec) {
    auto it = clients_.find(discord_id);
    if (it == clients_.end()) return;
    it->second.latest = spec;
    if (it->second.ready) apply(discord_id, it->second);
}

void SdkBackend::clear(const std::string& discord_id) {
    auto it = clients_.find(discord_id);
    if (it == clients_.end()) return;
    it->second.latest.reset();
    if (it->second.ready) apply(discord_id, it->second);
}

void SdkBackend::disconnect(const std::string& discord_id) {
    auto it = clients_.find(discord_id);
    if (it == clients_.end()) return;
    auto client = std::move(it->second.client);
    clients_.erase(it);
    if (client->GetStatus() != discordpp::Client::Status::Disconnected) client->Disconnect();
    retire(std::move(client));
}

void SdkBackend::update_token(const std::string& discord_id, const std::string& access_token) {
    auto it = clients_.find(discord_id);
    if (it == clients_.end()) return;
    it->second.client->UpdateToken(discordpp::AuthorizationTokenType::Bearer, access_token,
                                   guarded([discord_id](discordpp::ClientResult r) {
                                       if (!r.Successful())
                                           std::cerr << "relay: token update for " << discord_id
                                                     << " failed: " << r.Error() << '\n';
                                   }));
}

void SdkBackend::run_callbacks() {
    discordpp::RunCallbacks();
    const auto now = std::chrono::steady_clock::now();
    std::erase_if(retiring_, [now](const Retiring& r) { return r.until <= now; });
}

SdkBackend::Entry* SdkBackend::active(const std::string& id, const discordpp::Client* client) {
    auto it = clients_.find(id);
    if (it == clients_.end() || it->second.client.get() != client) return nullptr;
    return &it->second;
}

// Retires the client before notifying, so the report fires once and a disconnect() from the
// handler is a no-op.
void SdkBackend::lost(const std::string& id, bool auth_failed) {
    auto it = clients_.find(id);
    if (it == clients_.end()) return;
    auto client = std::move(it->second.client);
    clients_.erase(it);
    retire(std::move(client));
    if (on_connection_lost) on_connection_lost(id, auth_failed);
}

void SdkBackend::apply(const std::string& id, Entry& e) {
    if (e.latest) {
        e.client->UpdateRichPresence(to_activity(*e.latest), guarded([id](discordpp::ClientResult r) {
            if (!r.Successful()) std::cerr << "relay: presence update for " << id << " failed: " << r.Error() << '\n';
        }));
        e.applied = true;
    } else if (e.applied) {
        e.client->ClearRichPresence();
        e.applied = false;
    }
}

void SdkBackend::retire(std::shared_ptr<discordpp::Client> client) {
    retiring_.push_back({std::chrono::steady_clock::now() + kRetireFor, std::move(client)});
}

}  // namespace relay
