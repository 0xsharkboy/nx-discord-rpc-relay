// SPDX-License-Identifier: AGPL-3.0-or-later
#include "db.hpp"

#include <sqlite3.h>

#include <stdexcept>

namespace relay {

namespace {

constexpr int kSchemaVersion = 1;

[[noreturn]] void fail(sqlite3* db, const char* what) {
    throw std::runtime_error(std::string("sqlite: ") + what + ": " +
                             (db ? sqlite3_errmsg(db) : "out of memory"));
}

void exec(sqlite3* db, const char* sql) {
    char* err = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        std::string msg = err ? err : "unknown error";
        sqlite3_free(err);
        throw std::runtime_error("sqlite: " + msg);
    }
}

class Stmt {
public:
    Stmt(sqlite3* db, const char* sql) : db_(db) {
        if (sqlite3_prepare_v2(db, sql, -1, &s_, nullptr) != SQLITE_OK) fail(db, "prepare");
    }
    ~Stmt() { sqlite3_finalize(s_); }
    Stmt(const Stmt&) = delete;
    Stmt& operator=(const Stmt&) = delete;

    Stmt& text(int i, std::string_view v) {
        check(sqlite3_bind_text(s_, i, v.data() ? v.data() : "", static_cast<int>(v.size()),
                                 SQLITE_TRANSIENT));
        return *this;
    }
    Stmt& blob(int i, std::span<const uint8_t> v) {
        // A null pointer binds SQL NULL regardless of length.
        if (v.empty())
            check(sqlite3_bind_zeroblob(s_, i, 0));
        else
            check(sqlite3_bind_blob(s_, i, v.data(), static_cast<int>(v.size()), SQLITE_TRANSIENT));
        return *this;
    }
    Stmt& i64(int i, int64_t v) {
        check(sqlite3_bind_int64(s_, i, v));
        return *this;
    }

    bool step() {
        int rc = sqlite3_step(s_);
        if (rc == SQLITE_ROW) return true;
        if (rc == SQLITE_DONE) return false;
        fail(db_, "step");
    }
    void run() { step(); }

    std::string col_text(int i) const {
        auto* p = sqlite3_column_text(s_, i);
        return p ? std::string(reinterpret_cast<const char*>(p),
                               static_cast<size_t>(sqlite3_column_bytes(s_, i)))
                 : std::string();
    }
    std::vector<uint8_t> col_blob(int i) const {
        auto* p = static_cast<const uint8_t*>(sqlite3_column_blob(s_, i));
        return p ? std::vector<uint8_t>(p, p + sqlite3_column_bytes(s_, i))
                 : std::vector<uint8_t>();
    }
    int64_t col_i64(int i) const { return sqlite3_column_int64(s_, i); }

private:
    void check(int rc) {
        if (rc != SQLITE_OK) fail(db_, "bind");
    }
    sqlite3* db_;
    sqlite3_stmt* s_ = nullptr;
};

constexpr const char* kUserCols =
    "discord_id, username, key_hash, access_sealed, refresh_sealed, access_expires_at, "
    "link_broken";

User read_user(const Stmt& s) {
    User u;
    u.discord_id = s.col_text(0);
    u.username = s.col_text(1);
    u.key_hash = s.col_text(2);
    u.access_sealed = s.col_blob(3);
    u.refresh_sealed = s.col_blob(4);
    u.access_expires_at = s.col_i64(5);
    u.link_broken = s.col_i64(6) != 0;
    return u;
}

void migrate(sqlite3* db) {
    int version = 0;
    {
        Stmt s(db, "PRAGMA user_version");
        if (s.step()) version = static_cast<int>(s.col_i64(0));
    }
    if (version > kSchemaVersion) throw std::runtime_error("sqlite: database schema is newer");
    if (version == kSchemaVersion) return;

    exec(db, "BEGIN IMMEDIATE");
    try {
        exec(db,
             "CREATE TABLE IF NOT EXISTS users ("
             " discord_id TEXT PRIMARY KEY,"
             " username TEXT NOT NULL,"
             " key_hash TEXT NOT NULL UNIQUE,"
             " access_sealed BLOB NOT NULL,"
             " refresh_sealed BLOB NOT NULL,"
             " access_expires_at INTEGER NOT NULL,"
             " link_broken INTEGER NOT NULL DEFAULT 0);"
             "CREATE INDEX IF NOT EXISTS users_expires ON users(access_expires_at);"
             "CREATE TABLE IF NOT EXISTS published_icons ("
             " title_id TEXT PRIMARY KEY,"
             " sha256 TEXT NOT NULL,"
             " published_at INTEGER NOT NULL);"
             "CREATE TABLE IF NOT EXISTS votes ("
             " title_id TEXT NOT NULL,"
             " sha256 TEXT NOT NULL,"
             " discord_id TEXT NOT NULL,"
             " created_at INTEGER NOT NULL,"
             " PRIMARY KEY (title_id, sha256, discord_id));"
             "CREATE INDEX IF NOT EXISTS votes_created ON votes(created_at);"
             "CREATE TABLE IF NOT EXISTS blocked_hashes (sha256 TEXT PRIMARY KEY);"
             "PRAGMA user_version = 1");
        exec(db, "COMMIT");
    } catch (...) {
        sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}

}  // namespace

std::unique_ptr<Db> Db::open(const std::string& path) {
    std::unique_ptr<Db> self(new Db());
    int rc = sqlite3_open_v2(path.c_str(), &self->db_,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                             nullptr);
    if (rc != SQLITE_OK) fail(self->db_, "open");
    sqlite3_busy_timeout(self->db_, 5000);
    exec(self->db_, "PRAGMA journal_mode=WAL");
    exec(self->db_, "PRAGMA synchronous=NORMAL");
    migrate(self->db_);
    return self;
}

Db::~Db() {
    if (db_) sqlite3_close(db_);
}

void Db::upsert_user(const User& u) {
    std::lock_guard lock(mu_);
    exec(db_, "BEGIN IMMEDIATE");
    try {
        // key_hash is UNIQUE: drop any other row holding it so the upsert cannot conflict.
        Stmt(db_, "DELETE FROM users WHERE key_hash = ?1 AND discord_id != ?2")
            .text(1, u.key_hash)
            .text(2, u.discord_id)
            .run();
        Stmt(db_,
             "INSERT OR REPLACE INTO users "
             "(discord_id, username, key_hash, access_sealed, refresh_sealed, "
             "access_expires_at, link_broken) VALUES (?1,?2,?3,?4,?5,?6,?7)")
            .text(1, u.discord_id)
            .text(2, u.username)
            .text(3, u.key_hash)
            .blob(4, u.access_sealed)
            .blob(5, u.refresh_sealed)
            .i64(6, u.access_expires_at)
            .i64(7, u.link_broken ? 1 : 0)
            .run();
        exec(db_, "COMMIT");
    } catch (...) {
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}

std::optional<User> Db::user_by_key_hash(std::string_view key_hash) {
    std::lock_guard lock(mu_);
    Stmt s(db_, (std::string("SELECT ") + kUserCols + " FROM users WHERE key_hash = ?1").c_str());
    s.text(1, key_hash);
    if (!s.step()) return std::nullopt;
    return read_user(s);
}

std::optional<User> Db::user_by_discord_id(std::string_view discord_id) {
    std::lock_guard lock(mu_);
    Stmt s(db_,
           (std::string("SELECT ") + kUserCols + " FROM users WHERE discord_id = ?1").c_str());
    s.text(1, discord_id);
    if (!s.step()) return std::nullopt;
    return read_user(s);
}

bool Db::delete_user(std::string_view discord_id, std::string_view key_hash) {
    std::lock_guard lock(mu_);
    exec(db_, "BEGIN IMMEDIATE");
    try {
        Stmt(db_, "DELETE FROM users WHERE discord_id = ?1 AND key_hash = ?2")
            .text(1, discord_id)
            .text(2, key_hash)
            .run();
        const bool deleted = sqlite3_changes(db_) > 0;
        if (deleted) Stmt(db_, "DELETE FROM votes WHERE discord_id = ?1").text(1, discord_id).run();
        exec(db_, "COMMIT");
        return deleted;
    } catch (...) {
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}

void Db::set_link_broken(std::string_view discord_id, bool broken) {
    std::lock_guard lock(mu_);
    Stmt(db_, "UPDATE users SET link_broken = ?2 WHERE discord_id = ?1")
        .text(1, discord_id)
        .i64(2, broken ? 1 : 0)
        .run();
}

bool Db::update_tokens(std::string_view discord_id, std::string_view key_hash, std::span<const uint8_t> access,
                       std::span<const uint8_t> refresh, int64_t expires_at) {
    std::lock_guard lock(mu_);
    Stmt(db_,
         "UPDATE users SET access_sealed = ?2, refresh_sealed = ?3, access_expires_at = ?4 "
         "WHERE discord_id = ?1 AND key_hash = ?5")
        .text(1, discord_id)
        .blob(2, access)
        .blob(3, refresh)
        .i64(4, expires_at)
        .text(5, key_hash)
        .run();
    return sqlite3_changes(db_) > 0;
}

bool Db::break_link(std::string_view discord_id, std::string_view key_hash) {
    std::lock_guard lock(mu_);
    Stmt(db_, "UPDATE users SET link_broken = 1 WHERE discord_id = ?1 AND key_hash = ?2")
        .text(1, discord_id)
        .text(2, key_hash)
        .run();
    return sqlite3_changes(db_) > 0;
}

std::vector<User> Db::users_expiring_before(int64_t unix_s) {
    std::lock_guard lock(mu_);
    Stmt s(db_, (std::string("SELECT ") + kUserCols +
                 " FROM users WHERE access_expires_at < ?1 AND link_broken = 0 "
                 "ORDER BY access_expires_at")
                    .c_str());
    s.i64(1, unix_s);
    std::vector<User> out;
    while (s.step()) out.push_back(read_user(s));
    return out;
}

std::optional<IconRecord> Db::published_icon(std::string_view title_id) {
    std::lock_guard lock(mu_);
    Stmt s(db_, "SELECT title_id, sha256, published_at FROM published_icons WHERE title_id = ?1");
    s.text(1, title_id);
    if (!s.step()) return std::nullopt;
    return IconRecord{s.col_text(0), s.col_text(1), s.col_i64(2)};
}

void Db::publish_icon(std::string_view title_id, std::string_view sha256, int64_t now) {
    std::lock_guard lock(mu_);
    Stmt(db_,
         "INSERT OR REPLACE INTO published_icons (title_id, sha256, published_at) "
         "VALUES (?1,?2,?3)")
        .text(1, title_id)
        .text(2, sha256)
        .i64(3, now)
        .run();
}

void Db::unpublish_icon(std::string_view title_id) {
    std::lock_guard lock(mu_);
    Stmt(db_, "DELETE FROM published_icons WHERE title_id = ?1").text(1, title_id).run();
}

int Db::add_vote(std::string_view title_id, std::string_view sha256, std::string_view discord_id,
                 int64_t now) {
    std::lock_guard lock(mu_);
    Stmt(db_,
         "INSERT OR IGNORE INTO votes (title_id, sha256, discord_id, created_at) "
         "VALUES (?1,?2,?3,?4)")
        .text(1, title_id)
        .text(2, sha256)
        .text(3, discord_id)
        .i64(4, now)
        .run();
    Stmt s(db_, "SELECT COUNT(*) FROM votes WHERE title_id = ?1 AND sha256 = ?2");
    s.text(1, title_id).text(2, sha256);
    s.step();
    return static_cast<int>(s.col_i64(0));
}

void Db::block_hash(std::string_view sha256) {
    std::lock_guard lock(mu_);
    Stmt(db_, "INSERT OR IGNORE INTO blocked_hashes (sha256) VALUES (?1)").text(1, sha256).run();
}

bool Db::is_blocked(std::string_view sha256) {
    std::lock_guard lock(mu_);
    Stmt s(db_, "SELECT 1 FROM blocked_hashes WHERE sha256 = ?1");
    s.text(1, sha256);
    return s.step();
}

void Db::expire_votes(int64_t older_than) {
    std::lock_guard lock(mu_);
    Stmt(db_, "DELETE FROM votes WHERE created_at < ?1").i64(1, older_than).run();
}

}  // namespace relay
