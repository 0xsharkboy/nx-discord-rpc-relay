// SPDX-License-Identifier: AGPL-3.0-or-later
#include "api.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <chrono>
#include <exception>
#include <iostream>
#include <iterator>
#include <optional>
#include <string_view>

#include <nlohmann/json.hpp>

#include "badge_png.hpp"
#include "crypto.hpp"

namespace relay {

namespace {

using json = nlohmann::json;
using httplib::Request;
using httplib::Response;
using HandlerResponse = httplib::Server::HandlerResponse;

constexpr size_t kMaxNameBytes = 128;
constexpr size_t kMaxDetailsBytes = 128;
constexpr uint64_t kMaxElapsedS = 31'536'000;
constexpr size_t kMaxIpChars = 45;

thread_local std::optional<int64_t> t_request_start;

void send_json(Response& res, int status, const json& body) {
    res.status = status;
    res.set_content(body.dump(), "application/json");
}

void send_error(Response& res, int status, std::string_view code, std::string_view message) {
    send_json(res, status, json{{"error", code}, {"message", message}});
}

std::string generated_error_code(int status) {
    switch (status) {
    case 400: return "bad_request";
    case 404: return "not_found";
    case 405: return "method_not_allowed";
    case 411: return "length_required";
    case 413: return "too_large";
    case 414: return "uri_too_long";
    case 416: return "range_not_satisfiable";
    case 500: return "internal_error";
    default: return "http_" + std::to_string(status);
    }
}

std::string printable(std::string s) {
    for (char& c : s) {
        auto u = static_cast<unsigned char>(c);
        if (u < 0x21 || u > 0x7e) c = '?';
    }
    return s;
}

// The link id is a short-lived credential for the poll, so it never reaches the log.
std::string log_path(const std::string& path) {
    constexpr std::string_view prefix = "/v1/link/";
    if (path.size() <= prefix.size() || !path.starts_with(prefix)) return printable(path);
    auto slash = path.find('/', prefix.size());
    return printable(std::string(prefix) + ":id" + (slash == std::string::npos ? "" : path.substr(slash)));
}

std::string trim(std::string_view s) {
    const auto first = s.find_first_not_of(" \t");
    if (first == std::string_view::npos) return {};
    const auto last = s.find_last_not_of(" \t");
    return std::string(s.substr(first, last - first + 1));
}

std::optional<std::string> bearer_token(const Request& req) {
    const auto h = req.get_header_value("Authorization");
    constexpr std::string_view scheme = "bearer ";
    if (h.size() <= scheme.size()) return std::nullopt;
    for (size_t i = 0; i < scheme.size(); ++i)
        if (std::tolower(static_cast<unsigned char>(h[i])) != scheme[i]) return std::nullopt;
    auto token = trim(std::string_view(h).substr(scheme.size()));
    if (token.empty() || token.find_first_of(" \t") != std::string::npos) return std::nullopt;
    return token;
}

bool is_admin(const Deps& d, const std::optional<std::string>& token) {
    return token && d.config.admin_key && !d.config.admin_key->empty() &&
           constant_time_equal(*token, *d.config.admin_key);
}

std::optional<User> user_for(Deps& d, const std::optional<std::string>& token) {
    if (!token) return std::nullopt;
    return d.db.user_by_key_hash(sha256_hex(*token));
}

std::optional<User> require_user(Deps& d, const Request& req, Response& res) {
    auto user = user_for(d, bearer_token(req));
    if (!user) {
        send_error(res, 401, "unauthorized", "Missing or invalid API key");
        return user;
    }
    // Per version only: the key hashes stay in memory and only the totals are ever logged.
    if (d.version_counts) {
        if (auto v = parse_client_user_agent(req.get_header_value("User-Agent")))
            d.version_counts->seen(*v, user->key_hash);
        else
            d.version_counts->seen_other(user->key_hash);
    }
    return user;
}

// A console older than the configured minimum, by its own User-Agent. Any other client is served.
// DELETE /v1/me is never refused, so any console can always delete its data.
bool outdated_console(const Deps& d, const Request& req) {
    if (!d.config.min_client_version || !req.path.starts_with("/v1/")) return false;
    if (req.method == "DELETE" && req.path == "/v1/me") return false;
    auto v = parse_client_user_agent(req.get_header_value("User-Agent"));
    return v && older(*v, *d.config.min_client_version);
}

std::string client_ip(const Deps& d, const Request& req) {
    if (d.config.trust_proxy) {
        const auto xff = req.get_header_value("X-Forwarded-For");
        auto first = trim(std::string_view(xff).substr(0, xff.find(',')));
        // The hop is client-chosen: an absurd value must not become a large rate-limit key.
        if (!first.empty() && first.size() <= kMaxIpChars) return first;
    }
    return req.remote_addr;
}

// One IPv6 host usually owns a whole /64, so keying on the full address would let it rotate freely.
std::string ip_rate_key(const std::string& ip) {
    if (ip.find(':') == std::string::npos) return ip;
    in6_addr a{};
    if (inet_pton(AF_INET6, ip.c_str(), &a) != 1) return ip;
    char buf[INET6_ADDRSTRLEN] = {};
    if (IN6_IS_ADDR_V4MAPPED(&a)) {
        if (!inet_ntop(AF_INET, &a.s6_addr[12], buf, sizeof buf)) return ip;
        return buf;
    }
    std::fill(std::begin(a.s6_addr) + 8, std::end(a.s6_addr), uint8_t{0});
    if (!inet_ntop(AF_INET6, &a, buf, sizeof buf)) return ip;
    return std::string(buf) + "/64";
}

bool rate_limited(RateLimiter& limiter, const std::string& key, Response& res) {
    auto retry = limiter.take(key);
    if (!retry) return false;
    res.set_header("Retry-After", std::to_string(*retry));
    send_error(res, 429, "rate_limited", "Too many requests, retry later");
    return true;
}

// Replaces every byte that does not start or continue a well formed UTF-8 sequence with '?', which
// keeps the byte length. Consoles read game names from NACPs, which may hold Latin-1 or cut text.
std::string repair_utf8(std::string s) {
    const auto byte = [&s](size_t i) { return static_cast<unsigned char>(s[i]); };
    const auto in = [](unsigned char c, unsigned char lo, unsigned char hi) { return c >= lo && c <= hi; };
    size_t i = 0;
    while (i < s.size()) {
        const unsigned char c = byte(i);
        size_t len = 0;
        unsigned char lo = 0x80, hi = 0xBF;  // the allowed range of the second byte
        if (c < 0x80) len = 1;
        else if (in(c, 0xC2, 0xDF)) len = 2;
        else if (c == 0xE0) len = 3, lo = 0xA0;
        else if (in(c, 0xE1, 0xEC) || in(c, 0xEE, 0xEF)) len = 3;
        else if (c == 0xED) len = 3, hi = 0x9F;
        else if (c == 0xF0) len = 4, lo = 0x90;
        else if (in(c, 0xF1, 0xF3)) len = 4;
        else if (c == 0xF4) len = 4, hi = 0x8F;
        bool ok = len > 0 && i + len <= s.size();
        for (size_t k = 1; ok && k < len; ++k) ok = k == 1 ? in(byte(i + 1), lo, hi) : in(byte(i + k), 0x80, 0xBF);
        if (ok) {
            i += len;
        } else {
            s[i] = '?';
            ++i;
        }
    }
    return s;
}

std::optional<PresenceUpdate> parse_presence(const std::string& body, std::string& why) {
    auto j = json::parse(repair_utf8(body), nullptr, false);
    if (j.is_discarded() || !j.is_object()) {
        why = "Body must be a JSON object";
        return std::nullopt;
    }
    PresenceUpdate u;
    auto name = j.find("name");
    if (name == j.end() || !name->is_string() || name->get_ref<const std::string&>().empty() ||
        name->get_ref<const std::string&>().size() > kMaxNameBytes) {
        why = "name must be a string of 1 to 128 bytes";
        return std::nullopt;
    }
    u.name = name->get<std::string>();

    if (auto it = j.find("details"); it != j.end() && !it->is_null()) {
        if (!it->is_string() || it->get_ref<const std::string&>().size() > kMaxDetailsBytes) {
            why = "details must be a string of at most 128 bytes";
            return std::nullopt;
        }
        u.details = it->get<std::string>();
    }

    if (auto it = j.find("elapsed_s"); it != j.end() && !it->is_null()) {
        std::optional<uint64_t> v;
        if (it->is_number_unsigned()) v = it->get<uint64_t>();
        else if (it->is_number_integer() && it->get<int64_t>() >= 0) v = static_cast<uint64_t>(it->get<int64_t>());
        if (!v || *v > kMaxElapsedS) {
            why = "elapsed_s must be an integer from 0 to 31536000";
            return std::nullopt;
        }
        u.elapsed_s = static_cast<int64_t>(*v);
    }

    if (auto it = j.find("title_id"); it != j.end() && !it->is_null()) {
        if (!it->is_string() || !valid_title_id(it->get_ref<const std::string&>())) {
            why = "title_id must be 16 hex digits of a valid title";
            return std::nullopt;
        }
        u.title_id = normalize_title_id(it->get_ref<const std::string&>());
    }

    if (auto it = j.find("icon"); it != j.end() && !it->is_null()) {
        if (!it->is_string() || !Icons::valid_sha256(it->get_ref<const std::string&>())) {
            why = "icon must be 64 lowercase hex characters";
            return std::nullopt;
        }
        u.icon = it->get<std::string>();
    }

    if (auto it = j.find("badge"); it != j.end() && !it->is_null()) {
        if (!it->is_boolean()) {
            why = "badge must be a boolean";
            return std::nullopt;
        }
        u.badge = it->get<bool>();
    }
    return u;
}

void handle_link_start(Deps& d, const Request& req, Response& res) {
    if (rate_limited(d.link_limiter, ip_rate_key(client_ip(d, req)), res)) return;
    auto start = d.links.start();
    if (!start) return send_error(res, 502, "discord_unavailable", "Discord is unavailable, retry later");
    send_json(res, 200,
              json{{"link_id", start->link_id},
                   {"user_code", start->user_code},
                   {"verification_uri_complete", start->verification_uri_complete},
                   {"expires_in", start->expires_in},
                   {"interval", start->interval}});
}

void handle_link_poll(Deps& d, const Request& req, Response& res) {
    if (rate_limited(d.poll_limiter, ip_rate_key(client_ip(d, req)), res)) return;
    auto poll = d.links.poll(req.path_params.at("id"));
    switch (poll.state) {
    case LinkPoll::Pending: return send_json(res, 200, json{{"state", "pending"}});
    case LinkPoll::Expired: return send_json(res, 200, json{{"state", "expired"}});
    case LinkPoll::Denied: return send_json(res, 200, json{{"state", "denied"}});
    case LinkPoll::Linked:
        return send_json(res, 200,
                         json{{"state", "linked"},
                              {"api_key", poll.api_key},
                              {"username", poll.username},
                              {"discord_id", poll.discord_id},
                              {"avatar", poll.avatar ? json(*poll.avatar) : json(nullptr)}});
    case LinkPoll::Unknown: return send_error(res, 404, "unknown_link", "Unknown or expired link id");
    case LinkPoll::Error: break;
    }
    send_error(res, 502, "discord_unavailable", "Discord is unavailable, retry later");
}

void handle_me(Deps& d, const Request& req, Response& res) {
    auto user = require_user(d, req, res);
    if (!user) return;
    json presence = nullptr;
    if (auto cur = d.presence.current(user->discord_id))
        presence = json{{"name", cur->name}, {"details", cur->details}};
    json body{{"username", user->username}, {"link_broken", user->link_broken}, {"presence", presence}};
    // Until the refresher has read the identity, the avatar is unknown, which is not the same as none.
    if (user->identity_checked) {
        body["discord_id"] = user->discord_id;
        body["avatar"] = user->avatar ? json(*user->avatar) : json(nullptr);
    }
    send_json(res, 200, body);
}

void handle_unlink(Deps& d, const Request& req, Response& res) {
    auto user = require_user(d, req, res);
    if (!user) return;
    if (d.links.unlink(user->discord_id, user->key_hash)) d.presence.drop(user->discord_id);
    res.status = 204;
}

void handle_put_presence(Deps& d, const Request& req, Response& res) {
    auto user = require_user(d, req, res);
    if (!user) return;
    if (user->link_broken)
        return send_error(res, 409, "link_broken", "The Discord link is broken, link the account again");
    if (req.body.size() > kMaxPresenceBodyBytes)
        return send_error(res, 413, "too_large", "Body must be at most 4096 bytes");
    std::string why;
    auto update = parse_presence(req.body, why);
    if (!update) return send_error(res, 400, "invalid_body", why);
    // Only an accepted update is activity. Throttled from the row already loaded, so most PUTs do not
    // reach the database, and best effort: a failed write must not fail the update.
    if (const int64_t now = d.unix_s(); now - user->last_seen_at >= kLastSeenResolutionS) {
        try {
            d.db.touch_user(user->discord_id, user->key_hash, now);
        } catch (const std::exception& e) {
            std::cerr << "relay: recording activity failed: " << e.what() << '\n';
        }
    }
    if (!update->icon) {
        d.presence.put(user->discord_id, *update);
        res.status = 204;
        return;
    }
    bool need_icon = false;
    try {
        if (d.icons.usable(*update->icon)) {
            // Best effort, like the activity above.
            try {
                d.icons.touch(*update->icon);
            } catch (const std::exception& e) {
                std::cerr << "relay: recording icon use failed: " << e.what() << '\n';
            }
        } else if (d.db.is_blocked(*update->icon)) {
            // Shown as if the console had sent no hash, and never asked for.
            update->icon.reset();
        } else {
            need_icon = true;
        }
    } catch (const std::exception& e) {
        // An icon failure never breaks the presence: shown without the hash, and not asked for.
        std::cerr << "relay: checking the presence icon failed: " << e.what() << '\n';
        update->icon.reset();
        need_icon = false;
    }
    d.presence.put(user->discord_id, *update);
    send_json(res, 200, json{{"need_icon", need_icon}});
}

void handle_clear_presence(Deps& d, const Request& req, Response& res) {
    auto user = require_user(d, req, res);
    if (!user) return;
    d.presence.clear(user->discord_id);
    res.status = 204;
}

void handle_put_icon(Deps& d, const Request& req, Response& res) {
    const auto token = bearer_token(req);
    std::optional<User> user;
    if (!is_admin(d, token)) {
        user = user_for(d, token);
        if (!user) return send_error(res, 401, "unauthorized", "Missing or invalid API key");
        if (rate_limited(d.icon_limiter, user->key_hash, res)) return;
    }
    const auto& tid = req.path_params.at("tid");
    if (!valid_title_id(tid)) return send_error(res, 400, "invalid_icon", "Invalid title id");
    AdmitNewIcon admit_new;
    if (user) admit_new = [&d, &user] { return d.new_icon_limiter.take(user->key_hash); };
    auto out = d.icons.store(req.body, admit_new);
    switch (out.result) {
    case StoreResult::Stored:
        // An upload counts as a use: a v0.3 console never sends the hash in its presence. Best
        // effort: the file is stored.
        try {
            d.icons.touch(out.sha256);
        } catch (const std::exception& e) {
            std::cerr << "relay: recording icon use failed: " << e.what() << '\n';
        }
        if (user) d.presence.attach_icon(user->discord_id, normalize_title_id(tid), out.sha256);
        return send_json(res, 200, json{{"status", "stored"}});
    case StoreResult::Invalid:
        return send_error(res, 400, "invalid_icon", "Icon must be a 256x256 JPEG for a valid title id");
    case StoreResult::TooLarge: return send_error(res, 413, "too_large", "Icon must be at most 131072 bytes");
    case StoreResult::Blocked: return send_error(res, 400, "blocked", "This image was removed by an admin");
    case StoreResult::Full:
        return send_error(res, 503, "storage_full", "The relay stores no new icons for now, try again later");
    case StoreResult::Limited:
        res.set_header("Retry-After", std::to_string(out.retry_after_s));
        return send_error(res, 429, "rate_limited", "Too many new icons from this account, retry later");
    }
    send_error(res, 500, "internal_error", "Internal server error");
}

void handle_delete_icon(Deps& d, const Request& req, Response& res) {
    if (!is_admin(d, bearer_token(req))) return send_error(res, 401, "unauthorized", "Admin key required");
    // The path is an icon hash, or the title id of a legacy icon.
    const auto& target = req.path_params.at("tid");
    const bool removed = Icons::valid_sha256(target) ? d.icons.remove_hash(target) : d.icons.admin_delete(target);
    if (!removed) return send_error(res, 404, "not_found", "No icon to delete");
    d.presence.icons_changed();
    res.status = 204;
}

void handle_get_icon(Deps& d, const Request& req, Response& res) {
    const auto name = req.matches[1].str();
    std::optional<std::string> bytes =
        Icons::valid_sha256(name) ? d.icons.hash_bytes(name) : d.icons.published_bytes(name);
    if (!bytes || bytes->empty()) return send_error(res, 404, "not_found", "No such icon");
    res.status = 200;
    res.set_header("Cache-Control", "public, max-age=86400");
    res.set_content(std::move(*bytes), "image/jpeg");
}

}  // namespace

void register_routes(httplib::Server& svr, Deps& d) {
    if (!d.monotonic_ms)
        d.monotonic_ms = [] {
            return std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::steady_clock::now().time_since_epoch())
                .count();
        };
    if (!d.unix_s)
        d.unix_s = [] {
            return std::chrono::duration_cast<std::chrono::seconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                .count();
        };
    if (!d.log)
        d.log = [](const std::string& line) {
            std::cout << (line + '\n') << std::flush;
        };

    svr.set_payload_max_length(kMaxPayloadBytes);
    // One request per connection. httplib 0.18.7 decides to close only before routing, so a handler
    // cannot close after refusing a body it did not read (a chunked one): its bytes would be parsed
    // as the next request. The relay sits behind a local reverse proxy, so losing keep-alive on
    // that hop is cheap.
    svr.set_keep_alive_max_count(1);

    svr.set_pre_routing_handler([&d](const Request& req, Response& res) {
        t_request_start = d.monotonic_ms();
        // Before any other check, so an old console learns it must update whatever else is wrong.
        // The body is never read; the connection closes after one request anyway.
        if (outdated_console(d, req)) {
            const auto min = to_string(*d.config.min_client_version);
            send_json(res, 426,
                      json{{"error", "client_outdated"},
                           {"message", "This console's NX Discord RPC is too old for this relay, update to " + min +
                                           " or newer"},
                           {"min_version", min}});
            return HandlerResponse::Handled;
        }
        // This httplib version enforces the payload limit only on Content-Length bodies.
        if (req.has_header("Transfer-Encoding")) {
            send_error(res, 411, "length_required", "Send the body with a Content-Length header");
            return HandlerResponse::Handled;
        }
        // HTTP/1.1 gives a request without Content-Length an empty body, but httplib would read
        // until the read timeout. The Request object is not actually const in httplib.
        if (!req.has_header("Content-Length") &&
            (req.method == "POST" || req.method == "PUT" || req.method == "PATCH" || req.method == "DELETE"))
            const_cast<Request&>(req).set_header("Content-Length", "0");
        return HandlerResponse::Unhandled;
    });

    svr.set_error_handler([](const Request&, Response& res) {
        if (!res.body.empty()) return HandlerResponse::Unhandled;
        send_error(res, res.status, generated_error_code(res.status), httplib::status_message(res.status));
        return HandlerResponse::Handled;
    });

    svr.set_exception_handler([](const Request& req, Response& res, std::exception_ptr ep) {
        try {
            std::rethrow_exception(ep);
        } catch (const std::exception& e) {
            std::cerr << "relay: " << req.method << ' ' << log_path(req.path) << " failed: " << e.what() << '\n';
        } catch (...) {
            std::cerr << "relay: " << req.method << ' ' << log_path(req.path) << " failed\n";
        }
        res.headers.clear();
        send_error(res, 500, "internal_error", "Internal server error");
    });

    svr.set_logger([&d](const Request& req, const Response& res) {
        int64_t duration = 0;
        if (t_request_start) duration = d.monotonic_ms() - *t_request_start;
        t_request_start.reset();
        std::string line = printable(req.method) + ' ' + log_path(req.path) + ' ' + std::to_string(res.status) +
                           ' ' + std::to_string(duration) + "ms";
        // Why a request was refused. Every error message is a fixed string of the relay, never request
        // data. 404s are left out: scanners make most of them.
        if (res.status >= 400 && res.status != 404) {
            std::string code = generated_error_code(res.status);
            auto body = json::parse(res.body, nullptr, false);
            if (body.is_object() && body.value("error", json()).is_string() &&
                body.value("message", json()).is_string()) {
                code = body["error"].get<std::string>();
                line += ' ' + code + ": " + body["message"].get<std::string>();
            }
            if (d.refusal_counts) d.refusal_counts->refused(code);
        }
        d.log(line);
    });

    auto bind = [&d](void (*h)(Deps&, const Request&, Response&)) {
        return [&d, h](const Request& req, Response& res) { h(d, req, res); };
    };
    svr.Post("/v1/link", bind(handle_link_start));
    svr.Post("/v1/link/:id/poll", bind(handle_link_poll));
    svr.Get("/v1/me", bind(handle_me));
    svr.Delete("/v1/me", bind(handle_unlink));
    svr.Put("/v1/presence", bind(handle_put_presence));
    svr.Delete("/v1/presence", bind(handle_clear_presence));
    svr.Put("/v1/icons/:tid", bind(handle_put_icon));
    svr.Delete("/v1/icons/:tid", bind(handle_delete_icon));
    svr.Get(R"(/icons/([^/]+)\.jpg)", bind(handle_get_icon));
    svr.Get("/badge.png", [](const Request&, Response& res) {
        res.set_header("Cache-Control", "public, max-age=86400");
        res.set_content(reinterpret_cast<const char*>(kBadgePng), kBadgePngSize, "image/png");
    });
    svr.Get("/healthz", [](const Request&, Response& res) { res.set_content("ok", "text/plain"); });
}

}  // namespace relay
