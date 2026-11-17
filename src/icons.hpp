// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

#include "db.hpp"

namespace relay {

// 16 hex digits (either case), value >= 0x0100000000010000.
bool valid_title_id(std::string_view tid);
std::string normalize_title_id(std::string_view tid);

// Global cap on stored icon files, to protect the disk.
constexpr int64_t kDefaultMaxIconFiles = 10000;
// A stored icon unused for this long is deleted by cleanup, unless a live presence uses it.
constexpr int64_t kIconLifetimeS = 30 * 86400;

enum class StoreResult { Stored, Invalid, TooLarge, Blocked, Full, Limited };

// sha256 is set only for Stored, retry_after_s only for Limited.
struct StoreOutcome {
    StoreResult result;
    std::string sha256;
    int64_t retry_after_s = 0;
};

// Asked before a new file is written: nullopt admits it, else the seconds to wait.
using AdmitNewIcon = std::function<std::optional<int64_t>()>;

// Icon files named after the SHA-256 of the raw uploaded bytes, under <icons_dir>/h/. The stored
// file is the re-encoded image and is never re-hashed.
class Icons {
public:
    // `now` returns unix seconds.
    Icons(Db& db, std::string icons_dir, int64_t max_files, std::function<int64_t()> now);

    // Throws std::runtime_error if the icon file cannot be written (server I/O error); nothing is
    // recorded then. `admit_new`, when set, is asked only for bytes not stored yet and with room
    // left under the cap; a refusal gives Limited and stores nothing.
    StoreOutcome store(std::string_view jpeg, const AdmitNewIcon& admit_new = {});
    // The file row exists and the hash is not blocked.
    bool usable(std::string_view sha256);
    // Records a use of the hash, writing at most once a day per hash.
    void touch(std::string_view sha256);
    // The file path when the hash is usable and its file exists.
    std::optional<std::string> hash_path(std::string_view sha256);
    // Blocks the hash and deletes its file and row. False when the hash was unknown and already
    // blocked, or is not a valid hash.
    bool remove_hash(std::string_view sha256);
    // Deletes the files and rows unused for kIconLifetimeS and not in `in_use`. Returns how many.
    size_t cleanup(const std::unordered_set<std::string>& in_use);

    // Legacy title icons published before v0.4.0, served read-only. Nothing when its hash is blocked.
    std::optional<std::string> published_path(std::string_view title_id);
    // False when nothing is published for the title.
    bool admin_delete(std::string_view title_id);

    // 64 lowercase hex characters.
    static bool valid_sha256(std::string_view);

private:
    std::string path_for(const std::string& tid) const;
    std::string hash_file(std::string_view sha256) const;

    Db& db_;
    std::string dir_;
    int64_t max_files_;
    std::function<int64_t()> now_;
    std::mutex mu_;
    // Last touch_icon_file per hash, to write at most once a day.
    std::unordered_map<std::string, int64_t> touched_;
};

// The large image of a presence: the usable icon hash, else the legacy icon published for the
// title, else "switch_logo". `base_url` has no trailing slash.
std::string presence_image(Icons& icons, const std::string& base_url, const std::optional<std::string>& title_id,
                           const std::optional<std::string>& icon);

}  // namespace relay
