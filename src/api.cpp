#include "api.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <chrono>
#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <string_view>

#include <nlohmann/json.hpp>

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
    if (!user) send_error(res, 401, "unauthorized", "Missing or invalid API key");
    return user;
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

std::optional<PresenceUpdate> parse_presence(const std::string& body, std::string& why) {
    auto j = json::parse(body, nullptr, false);
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
                         json{{"state", "linked"}, {"api_key", poll.api_key}, {"username", poll.username}});
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
    send_json(res, 200,
              json{{"username", user->username}, {"link_broken", user->link_broken}, {"presence", presence}});
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
    d.presence.put(user->discord_id, *update);
    res.status = 204;
}

void handle_clear_presence(Deps& d, const Request& req, Response& res) {
    auto user = require_user(d, req, res);
    if (!user) return;
    d.presence.clear(user->discord_id);
    res.status = 204;
}

void handle_put_icon(Deps& d, const Request& req, Response& res) {
    const auto token = bearer_token(req);
    const bool admin = is_admin(d, token);
    std::string voter = "admin";
    if (!admin) {
        auto user = user_for(d, token);
        if (!user) return send_error(res, 401, "unauthorized", "Missing or invalid API key");
        if (rate_limited(d.icon_limiter, user->key_hash, res)) return;
        voter = user->discord_id;
    }
    const auto& tid = req.path_params.at("tid");
    if (!valid_title_id(tid)) return send_error(res, 400, "invalid_icon", "Invalid title id");
    auto out = d.icons.submit(tid, req.body, voter, admin);
    switch (out.result) {
    case IconResult::Published: return send_json(res, 200, json{{"status", "published"}});
    case IconResult::Pending:
        return send_json(res, 202, json{{"status", "pending"}, {"votes", out.votes}, {"needed", out.needed}});
    case IconResult::AlreadyPublished: return send_json(res, 200, json{{"status", "already_published"}});
    case IconResult::Invalid:
        return send_error(res, 400, "invalid_icon", "Icon must be a 256x256 JPEG for a valid title id");
    case IconResult::TooLarge: return send_error(res, 413, "too_large", "Icon must be at most 131072 bytes");
    case IconResult::Blocked: return send_error(res, 400, "blocked", "This image was removed by an admin");
    }
    send_error(res, 500, "internal_error", "Internal server error");
}

void handle_delete_icon(Deps& d, const Request& req, Response& res) {
    if (!is_admin(d, bearer_token(req))) return send_error(res, 401, "unauthorized", "Admin key required");
    if (!d.icons.admin_delete(req.path_params.at("tid")))
        return send_error(res, 404, "not_found", "No published icon for this title");
    res.status = 204;
}

void handle_get_icon(Deps& d, const Request& req, Response& res) {
    std::optional<std::string> path = d.icons.published_path(req.matches[1].str());
    std::string bytes;
    if (path) {
        std::ifstream f(*path, std::ios::binary);
        if (f) bytes.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
    }
    if (bytes.empty()) return send_error(res, 404, "not_found", "No published icon for this title");
    res.status = 200;
    res.set_header("Cache-Control", "public, max-age=86400");
    res.set_content(std::move(bytes), "image/jpeg");
}

}  // namespace

void register_routes(httplib::Server& svr, Deps& d) {
    if (!d.monotonic_ms)
        d.monotonic_ms = [] {
            return std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::steady_clock::now().time_since_epoch())
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
        d.log(printable(req.method) + ' ' + log_path(req.path) + ' ' + std::to_string(res.status) + ' ' +
              std::to_string(duration) + "ms");
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
    svr.Get("/healthz", [](const Request&, Response& res) { res.set_content("ok", "text/plain"); });
}

}  // namespace relay
