#include "oauth.hpp"

#include <httplib.h>

#include <nlohmann/json.hpp>
#include <vector>

#include "crypto.hpp"
#include "version.hpp"

namespace relay {
namespace {

using nlohmann::json;

constexpr const char* kHost = "discord.com";
constexpr const char* kScope = "openid sdk.social_layer_presence";

std::optional<json> parse_object(std::string_view body) {
    auto j = json::parse(body.begin(), body.end(), nullptr, false);
    if (j.is_discarded() || !j.is_object()) return std::nullopt;
    return j;
}

std::string str_field(const json& j, const char* key) {
    auto it = j.find(key);
    return it != j.end() && it->is_string() ? it->get<std::string>() : std::string();
}

std::optional<Tokens> tokens_from(const json& j) {
    Tokens t;
    t.access_token = str_field(j, "access_token");
    t.refresh_token = str_field(j, "refresh_token");
    auto it = j.find("expires_in");
    if (t.access_token.empty() || t.refresh_token.empty() || it == j.end() || !it->is_number_integer())
        return std::nullopt;
    t.expires_in = it->get<int64_t>();
    return t;
}

std::string form_encode(const std::vector<std::pair<std::string, std::string>>& kv) {
    std::string out;
    for (const auto& [k, v] : kv) {
        if (!out.empty()) out += '&';
        out += httplib::detail::encode_query_param(k) + '=' + httplib::detail::encode_query_param(v);
    }
    return out;
}

}  // namespace

std::optional<std::pair<std::string, std::string>> id_token_identity(std::string_view id_token) {
    auto first = id_token.find('.');
    if (first == std::string_view::npos) return std::nullopt;
    auto rest = id_token.substr(first + 1);
    auto second = rest.find('.');
    if (second == std::string_view::npos) return std::nullopt;
    auto seg = rest.substr(0, second);
    while (!seg.empty() && seg.back() == '=') seg.remove_suffix(1);
    auto bytes = base64url_decode(seg);
    if (!bytes) return std::nullopt;
    auto j = parse_object({reinterpret_cast<const char*>(bytes->data()), bytes->size()});
    if (!j) return std::nullopt;
    auto sub = j->find("sub");
    if (sub == j->end() || !sub->is_string() || sub->get<std::string>().empty()) return std::nullopt;
    return std::make_pair(sub->get<std::string>(), str_field(*j, "preferred_username"));
}

PollResult parse_token_response(int http_status, std::string_view body) {
    if (http_status == 429) return {PollState::SlowDown, std::nullopt};
    auto j = parse_object(body);
    if (!j) return {PollState::Error, std::nullopt};
    if (http_status == 400) {
        auto err = str_field(*j, "error");
        if (err == "authorization_pending") return {PollState::Pending, std::nullopt};
        if (err == "slow_down") return {PollState::SlowDown, std::nullopt};
        if (err == "expired_token") return {PollState::Expired, std::nullopt};
        if (err == "access_denied") return {PollState::Denied, std::nullopt};
        return {PollState::Error, std::nullopt};
    }
    if (http_status != 200) return {PollState::Error, std::nullopt};
    auto t = tokens_from(*j);
    if (!t) return {PollState::Error, std::nullopt};
    auto id = id_token_identity(str_field(*j, "id_token"));
    if (!id) return {PollState::Error, std::nullopt};
    t->discord_id = id->first;
    t->username = id->second;
    return {PollState::Granted, std::move(t)};
}

RefreshResult parse_refresh_response(int http_status, std::string_view body) {
    using S = RefreshResult::State;
    if (http_status == 401) return {S::Revoked, std::nullopt};
    auto j = parse_object(body);
    if (!j) return {S::Transient, std::nullopt};
    if (http_status == 400 && str_field(*j, "error") == "invalid_grant") return {S::Revoked, std::nullopt};
    if (http_status != 200) return {S::Transient, std::nullopt};
    auto t = tokens_from(*j);
    if (!t) return {S::Transient, std::nullopt};
    if (auto id = id_token_identity(str_field(*j, "id_token"))) {
        t->discord_id = id->first;
        t->username = id->second;
    }
    return {S::Refreshed, std::move(t)};
}

std::optional<DeviceAuth> parse_device_response(int http_status, std::string_view body) {
    if (http_status != 200) return std::nullopt;
    auto j = parse_object(body);
    if (!j) return std::nullopt;
    DeviceAuth d;
    d.device_code = str_field(*j, "device_code");
    d.user_code = str_field(*j, "user_code");
    auto uri = str_field(*j, "verification_uri");
    d.verification_uri_complete = str_field(*j, "verification_uri_complete");
    if (d.device_code.empty() || d.user_code.empty()) return std::nullopt;
    if (d.verification_uri_complete.empty()) {
        if (uri.empty()) return std::nullopt;
        d.verification_uri_complete = uri + "?user_code=" + d.user_code;
    }
    if (auto it = j->find("expires_in"); it != j->end() && it->is_number_integer())
        d.expires_in = it->get<int>();
    if (auto it = j->find("interval"); it != j->end() && it->is_number_integer())
        d.interval = it->get<int>();
    return d;
}

DiscordOAuth::DiscordOAuth(const Config& cfg)
    : client_id_(cfg.client_id), client_secret_(cfg.client_secret) {}

namespace {

struct HttpReply {
    int status = 0;
    std::string body;
};

HttpReply post_form(const std::string& id, const std::string& secret, const char* path,
                    const std::vector<std::pair<std::string, std::string>>& form) {
    httplib::SSLClient cli(kHost, 443);
    cli.set_connection_timeout(10, 0);
    cli.set_read_timeout(10, 0);
    cli.set_write_timeout(10, 0);
    cli.enable_server_certificate_verification(true);
    cli.set_basic_auth(id, secret);
    std::string ua = "nx-discord-rpc-relay (https://github.com/0xsharkboy/nx-discord-rpc, " +
                     std::string(version()) + ")";
    httplib::Headers headers{{"User-Agent", ua}};
    auto res = cli.Post(path, headers, form_encode(form), "application/x-www-form-urlencoded");
    if (!res) return {};
    return {res->status, std::move(res->body)};
}

}  // namespace

std::optional<DeviceAuth> DiscordOAuth::device_authorize() {
    auto r = post_form(client_id_, client_secret_, "/api/v10/oauth2/device/authorize", {{"scope", kScope}});
    return parse_device_response(r.status, r.body);
}

PollResult DiscordOAuth::poll(const std::string& device_code) {
    auto r = post_form(client_id_, client_secret_, "/api/v10/oauth2/token",
                       {{"grant_type", "urn:ietf:params:oauth:grant-type:device_code"},
                        {"device_code", device_code}});
    return parse_token_response(r.status, r.body);
}

RefreshResult DiscordOAuth::refresh(const std::string& refresh_token) {
    auto r = post_form(client_id_, client_secret_, "/api/v10/oauth2/token",
                       {{"grant_type", "refresh_token"}, {"refresh_token", refresh_token}});
    return parse_refresh_response(r.status, r.body);
}

void DiscordOAuth::revoke(const std::string& token) {
    post_form(client_id_, client_secret_, "/api/v10/oauth2/token/revoke", {{"token", token}});
}

}  // namespace relay
