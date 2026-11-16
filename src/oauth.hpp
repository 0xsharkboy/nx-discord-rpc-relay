// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include "config.hpp"

namespace relay {

struct DeviceAuth {
    std::string device_code, user_code, verification_uri_complete;
    int expires_in = 0, interval = 5;
};

struct Tokens {
    std::string access_token, refresh_token;
    int64_t expires_in = 0;
    std::string discord_id, username;
};

enum class PollState { Pending, SlowDown, Expired, Denied, Granted, Error };

struct PollResult {
    PollState state = PollState::Error;
    std::optional<Tokens> tokens;
};

struct RefreshResult {
    // ClientError: Discord refused the relay's own credentials (wrong or rotated client secret).
    // It says nothing about the user's grant, so it is handled like Transient.
    enum class State { Refreshed, Revoked, Transient, ClientError } state = State::Transient;
    std::optional<Tokens> tokens;
};

class IOAuth {
public:
    virtual ~IOAuth() = default;
    virtual std::optional<DeviceAuth> device_authorize() = 0;
    virtual PollResult poll(const std::string& device_code) = 0;
    virtual RefreshResult refresh(const std::string& refresh_token) = 0;
    virtual void revoke(const std::string& token) = 0;  // best effort
};

class DiscordOAuth : public IOAuth {
public:
    explicit DiscordOAuth(const Config& cfg);
    std::optional<DeviceAuth> device_authorize() override;
    PollResult poll(const std::string& device_code) override;
    RefreshResult refresh(const std::string& refresh_token) override;
    void revoke(const std::string& token) override;

private:
    std::string client_id_, client_secret_;
};

// {sub, preferred_username or ""}. The signature is not checked: the token comes
// straight from Discord over TLS.
std::optional<std::pair<std::string, std::string>> id_token_identity(std::string_view id_token);

// http_status 0 means the request never completed. 429 maps to SlowDown.
PollResult parse_token_response(int http_status, std::string_view body);

// Identity from GET /oauth2/@me. Requires 200 and user.id; when application.id is present it must
// match, so a token minted for another app is never linked. username may be empty.
std::optional<std::pair<std::string, std::string>> parse_identity_response(
    int http_status, std::string_view body, std::string_view expected_application_id);

// ClientError for invalid_client or unauthorized_client at any status. Revoked only for a
// definitive rejection of the grant (invalid_grant, or any other 401); everything else that is not
// a valid 200 is Transient so an outage never breaks links.
RefreshResult parse_refresh_response(int http_status, std::string_view body);

// Returns nullopt if the body lacks a usable device_code/user_code/verification_uri.
std::optional<DeviceAuth> parse_device_response(int http_status, std::string_view body);

}  // namespace relay
