#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

struct sqlite3;

namespace relay {

struct User {
    std::string discord_id, username, key_hash;
    std::vector<uint8_t> access_sealed, refresh_sealed;
    int64_t access_expires_at = 0;
    bool link_broken = false;
};

struct IconRecord {
    std::string title_id, sha256;
    int64_t published_at;
};

class Db {
public:
    static std::unique_ptr<Db> open(const std::string& path);
    ~Db();
    Db(const Db&) = delete;
    Db& operator=(const Db&) = delete;

    void upsert_user(const User&);
    std::optional<User> user_by_key_hash(std::string_view);
    std::optional<User> user_by_discord_id(std::string_view);
    void delete_user(std::string_view discord_id);
    void set_link_broken(std::string_view discord_id, bool);
    void update_tokens(std::string_view discord_id, std::span<const uint8_t> access,
                       std::span<const uint8_t> refresh, int64_t expires_at);
    // Excludes users whose link is broken.
    std::vector<User> users_expiring_before(int64_t unix_s);

    std::optional<IconRecord> published_icon(std::string_view title_id);
    void publish_icon(std::string_view title_id, std::string_view sha256, int64_t now);
    void unpublish_icon(std::string_view title_id);
    // Idempotent per (title, hash, voter); returns the distinct voter count for (title, hash).
    int add_vote(std::string_view title_id, std::string_view sha256, std::string_view discord_id,
                 int64_t now);
    void block_hash(std::string_view sha256);
    bool is_blocked(std::string_view sha256);
    void expire_votes(int64_t older_than);

private:
    Db() = default;
    sqlite3* db_ = nullptr;
    std::mutex mu_;
};

}  // namespace relay
