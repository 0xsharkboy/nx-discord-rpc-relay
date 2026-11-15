#pragma once

#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

#include "db.hpp"

namespace relay {

// 16 hex digits (either case), value >= 0x0100000000010000.
bool valid_title_id(std::string_view tid);
std::string normalize_title_id(std::string_view tid);

enum class IconResult { Published, Pending, AlreadyPublished, Invalid, TooLarge, Blocked };

// votes/needed are set only for Pending (distinct voters so far / threshold).
struct IconOutcome {
    IconResult result;
    int votes = 0;
    int needed = 0;
};

class Icons {
public:
    // `now` returns unix seconds.
    Icons(Db& db, std::string icons_dir, int threshold, std::function<int64_t()> now);

    // Throws std::runtime_error if the icon file cannot be written (server I/O error); the vote
    // recorded before the write stays.
    IconOutcome submit(std::string_view title_id, std::string_view jpeg,
                       std::string_view voter_discord_id, bool admin);
    std::optional<std::string> published_path(std::string_view title_id);
    // False when nothing is published for the title.
    bool admin_delete(std::string_view title_id);

    // Fires once per publish or replace, never for Pending, outside the internal lock.
    std::function<void(const std::string& title_id)> on_published;

private:
    std::string path_for(const std::string& tid) const;

    Db& db_;
    std::string dir_;
    int threshold_;
    std::function<int64_t()> now_;
    std::mutex mu_;
};

}  // namespace relay
