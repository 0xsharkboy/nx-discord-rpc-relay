// SPDX-License-Identifier: AGPL-3.0-or-later
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
    std::optional<std::string> avatar;
    bool link_broken = false;
    // False until the username and avatar were read from Discord for this link.
    bool identity_checked = false;
    // Unix seconds of the last accepted PUT /v1/presence (or of the link), kept to within
    // kLastSeenResolutionS.
    int64_t last_seen_at = 0;
};

// last_seen_at is rewritten at most this often per user, to limit writes.
constexpr int64_t kLastSeenResolutionS = 3600;

struct IconRecord {
    std::string title_id, sha256;
    int64_t published_at;
};

class Db {
public:
    // Lookups for the SDK thread. They run on a second, read-only connection with its own lock, so
    // they never wait behind a write on the main connection (WAL), and see every write committed
    // before they start. A ":memory:" database has no second connection: they share the main one.
    class Reader {
    public:
        std::optional<User> user_by_discord_id(std::string_view);
        // The hash has an icon file row and is not blocked.
        bool icon_usable(std::string_view sha256);
        // The legacy icon published for the title, unless its hash is blocked.
        std::optional<IconRecord> unblocked_published_icon(std::string_view title_id);

    private:
        friend class Db;
        Reader() = default;
        sqlite3* db_ = nullptr;
        std::mutex* mu_ = nullptr;
    };

    static std::unique_ptr<Db> open(const std::string& path);
    ~Db();
    Db(const Db&) = delete;
    Db& operator=(const Db&) = delete;

    void upsert_user(const User&);
    std::optional<User> user_by_key_hash(std::string_view);
    std::optional<User> user_by_discord_id(std::string_view);
    // Deletes the row only while it still holds `key_hash`. Returns whether a row was deleted.
    bool delete_user(std::string_view discord_id, std::string_view key_hash);
    // Same as delete_user, but only while the row was also last seen before `cutoff`, so a user seen
    // again since a sweep took its snapshot is kept.
    bool delete_inactive_user(std::string_view discord_id, std::string_view key_hash, int64_t cutoff);
    // Sets last_seen_at to `now` unless it was set less than kLastSeenResolutionS before. Guarded by
    // `key_hash` like the updates below. Returns whether a row changed.
    bool touch_user(std::string_view discord_id, std::string_view key_hash, int64_t now);
    // Includes users whose link is broken. Oldest first.
    std::vector<User> users_inactive_before(int64_t unix_s);
    void set_link_broken(std::string_view discord_id, bool);
    // The guarded updates below change the row only while it still holds `key_hash`, so work based
    // on a snapshot taken before a relink or an unlink cannot touch the new link. They return whether
    // a row changed.
    bool update_tokens(std::string_view discord_id, std::string_view key_hash, std::span<const uint8_t> access,
                       std::span<const uint8_t> refresh, int64_t expires_at);
    bool break_link(std::string_view discord_id, std::string_view key_hash);
    // Rewrites the username and avatar (nullopt clears it) and marks the identity checked. Returns
    // whether a row changed.
    bool update_identity(std::string_view discord_id, std::string_view key_hash, std::string_view username,
                         const std::optional<std::string>& avatar);
    // Users whose identity was never read, excluding those whose link is broken.
    std::vector<User> users_identity_unchecked();
    // Excludes users whose link is broken.
    std::vector<User> users_expiring_before(int64_t unix_s);

    // Icons published per title before v0.4.0, kept read-only as a fallback.
    std::optional<IconRecord> published_icon(std::string_view title_id);
    void unpublish_icon(std::string_view title_id);
    void block_hash(std::string_view sha256);
    bool is_blocked(std::string_view sha256);

    // Stored icon files, keyed by the SHA-256 of the uploaded bytes. No user or title is recorded.
    // Inserts or ignores; a new row gets `now` as both its creation and last-used time.
    void add_icon_file(std::string_view sha256, int64_t now);
    bool has_icon_file(std::string_view sha256);
    void touch_icon_file(std::string_view sha256, int64_t now);
    // Hashes whose last use is strictly before `older_than`.
    std::vector<std::string> icon_files_unused_since(int64_t older_than);
    void delete_icon_file(std::string_view sha256);
    int64_t icon_file_count();

    Reader& reader() { return reader_; }

private:
    bool delete_user_where(std::string_view discord_id, std::string_view key_hash,
                           std::optional<int64_t> seen_before);
    Db() = default;
    sqlite3* db_ = nullptr;
    std::mutex mu_;
    // Null for ":memory:".
    sqlite3* read_db_ = nullptr;
    std::mutex read_mu_;
    Reader reader_;
};

}  // namespace relay
