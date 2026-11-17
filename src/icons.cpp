// SPDX-License-Identifier: AGPL-3.0-or-later
#include "icons.hpp"

#include <cctype>
#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <vector>

#include <stb_image.h>
#include <stb_image_write.h>

#include "crypto.hpp"

namespace relay {
namespace fs = std::filesystem;

namespace {

constexpr size_t kMaxBytes = 131072;
constexpr int kSide = 256;
constexpr uint64_t kMinTitleId = 0x0100000000010000ULL;
constexpr int kJpegQuality = 90;
// An icon's last-used time is rewritten at most this often.
constexpr int64_t kTouchEveryS = 86400;

struct StbiDeleter {
    void operator()(unsigned char* p) const { stbi_image_free(p); }
};

void append_cb(void* ctx, void* data, int size) {
    static_cast<std::string*>(ctx)->append(static_cast<const char*>(data), static_cast<size_t>(size));
}

// Decodes only a strict 256x256 JPEG; the header is checked before any pixel decode.
std::optional<std::string> reencode(std::string_view jpeg) {
    if (jpeg.size() < 3 || static_cast<unsigned char>(jpeg[0]) != 0xFF ||
        static_cast<unsigned char>(jpeg[1]) != 0xD8 || static_cast<unsigned char>(jpeg[2]) != 0xFF)
        return std::nullopt;
    auto* data = reinterpret_cast<const unsigned char*>(jpeg.data());
    int len = static_cast<int>(jpeg.size());
    int w = 0, h = 0, c = 0;
    if (!stbi_info_from_memory(data, len, &w, &h, &c) || w != kSide || h != kSide)
        return std::nullopt;
    std::unique_ptr<unsigned char, StbiDeleter> px(stbi_load_from_memory(data, len, &w, &h, &c, 3));
    if (!px || w != kSide || h != kSide) return std::nullopt;
    std::string out;
    if (!stbi_write_jpg_to_func(append_cb, &out, kSide, kSide, 3, px.get(), kJpegQuality))
        return std::nullopt;
    return out;
}

bool write_atomic(const fs::path& dest, const std::string& bytes) {
    fs::path tmp = dest;
    tmp += ".tmp";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        f.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        f.flush();
        if (!f) {
            std::error_code ec;
            fs::remove(tmp, ec);
            return false;
        }
    }
    std::error_code ec;
    fs::rename(tmp, dest, ec);
    if (ec) {
        fs::remove(tmp, ec);
        return false;
    }
    return true;
}

}  // namespace

bool valid_title_id(std::string_view tid) {
    if (tid.size() != 16) return false;
    uint64_t v = 0;
    for (char ch : tid) {
        unsigned char c = static_cast<unsigned char>(ch);
        int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else return false;
        v = (v << 4) | static_cast<uint64_t>(d);
    }
    return v >= kMinTitleId;
}

std::string normalize_title_id(std::string_view tid) {
    std::string s(tid);
    for (char& c : s) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return s;
}

Icons::Icons(Db& db, std::string icons_dir, int64_t max_files, std::function<int64_t()> now)
    : db_(db), dir_(std::move(icons_dir)), max_files_(max_files), now_(std::move(now)) {
    fs::create_directories(fs::path(dir_) / "h");
}

bool Icons::valid_sha256(std::string_view s) {
    if (s.size() != 64) return false;
    for (char c : s)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}

std::string Icons::path_for(const std::string& tid) const {
    return (fs::path(dir_) / (tid + ".jpg")).string();
}

std::string Icons::hash_file(std::string_view sha256) const {
    return (fs::path(dir_) / "h" / (std::string(sha256) + ".jpg")).string();
}

StoreOutcome Icons::store(std::string_view jpeg, const AdmitNewIcon& admit_new) {
    if (jpeg.empty()) return {StoreResult::Invalid, {}};
    if (jpeg.size() > kMaxBytes) return {StoreResult::TooLarge, {}};
    auto encoded = reencode(jpeg);
    if (!encoded) return {StoreResult::Invalid, {}};

    std::string hash = sha256_hex(jpeg);
    std::lock_guard lk(mu_);
    if (db_.is_blocked(hash)) return {StoreResult::Blocked, {}};
    const auto path = hash_file(hash);
    std::error_code ec;
    if (db_.has_icon_file(hash)) {
        // Known bytes: nothing to write, unless the file went missing.
        if (!fs::exists(path, ec) && !write_atomic(path, *encoded))
            throw std::runtime_error("failed to write icon file");
        return {StoreResult::Stored, std::move(hash)};
    }
    if (db_.icon_file_count() >= max_files_) return {StoreResult::Full, {}};
    if (admit_new) {
        if (auto wait_s = admit_new()) return {StoreResult::Limited, {}, *wait_s};
    }
    if (!write_atomic(path, *encoded)) throw std::runtime_error("failed to write icon file");
    db_.add_icon_file(hash, now_());
    return {StoreResult::Stored, std::move(hash)};
}

bool Icons::usable(std::string_view sha256) {
    if (!valid_sha256(sha256)) return false;
    std::lock_guard lk(mu_);
    return db_.has_icon_file(sha256) && !db_.is_blocked(sha256);
}

void Icons::touch(std::string_view sha256) {
    if (!valid_sha256(sha256)) return;
    const int64_t now = now_();
    std::lock_guard lk(mu_);
    auto [it, inserted] = touched_.try_emplace(std::string(sha256), now);
    if (!inserted) {
        if (now - it->second < kTouchEveryS) return;
        it->second = now;
    }
    db_.touch_icon_file(sha256, now);
}

std::optional<std::string> Icons::hash_path(std::string_view sha256) {
    if (!valid_sha256(sha256)) return std::nullopt;
    std::lock_guard lk(mu_);
    if (!db_.has_icon_file(sha256) || db_.is_blocked(sha256)) return std::nullopt;
    auto p = hash_file(sha256);
    std::error_code ec;
    if (!fs::exists(p, ec)) return std::nullopt;
    return p;
}

bool Icons::remove_hash(std::string_view sha256) {
    if (!valid_sha256(sha256)) return false;
    std::lock_guard lk(mu_);
    const bool known = db_.has_icon_file(sha256);
    const bool was_blocked = db_.is_blocked(sha256);
    db_.block_hash(sha256);
    std::error_code ec;
    fs::remove(hash_file(sha256), ec);
    db_.delete_icon_file(sha256);
    touched_.erase(std::string(sha256));
    return known || !was_blocked;
}

size_t Icons::cleanup(const std::unordered_set<std::string>& in_use) {
    const int64_t now = now_();
    std::lock_guard lk(mu_);
    size_t removed = 0;
    for (const auto& hash : db_.icon_files_unused_since(now - kIconLifetimeS)) {
        if (in_use.contains(hash)) continue;
        // Only well formed names reach the disk.
        if (valid_sha256(hash)) {
            std::error_code ec;
            fs::remove(hash_file(hash), ec);
        }
        db_.delete_icon_file(hash);
        ++removed;
    }
    std::erase_if(touched_, [now](const auto& kv) { return now - kv.second >= kTouchEveryS; });
    return removed;
}

std::optional<std::string> Icons::published_path(std::string_view title_id) {
    if (!valid_title_id(title_id)) return std::nullopt;
    const std::string tid = normalize_title_id(title_id);
    std::lock_guard lk(mu_);
    // A hash removed by an admin hides the legacy icon of every title that has the same bytes.
    auto rec = db_.published_icon(tid);
    if (!rec || db_.is_blocked(rec->sha256)) return std::nullopt;
    auto p = path_for(tid);
    std::error_code ec;
    if (!fs::exists(p, ec)) return std::nullopt;
    return p;
}

// No Icons lock: these only read the database, in one statement each, and the file system.
bool Icons::reader_usable(std::string_view sha256) {
    return valid_sha256(sha256) && db_.reader().icon_usable(sha256);
}

std::optional<std::string> Icons::reader_published_path(std::string_view title_id) {
    if (!valid_title_id(title_id)) return std::nullopt;
    const std::string tid = normalize_title_id(title_id);
    if (!db_.reader().unblocked_published_icon(tid)) return std::nullopt;
    auto p = path_for(tid);
    std::error_code ec;
    if (!fs::exists(p, ec)) return std::nullopt;
    return p;
}

bool Icons::admin_delete(std::string_view title_id) {
    if (!valid_title_id(title_id)) return false;
    const std::string tid = normalize_title_id(title_id);
    std::lock_guard lk(mu_);
    auto rec = db_.published_icon(tid);
    if (!rec) return false;
    db_.unpublish_icon(tid);
    db_.block_hash(rec->sha256);
    std::error_code ec;
    fs::remove(path_for(tid), ec);
    return true;
}

std::string presence_image(Icons& icons, const std::string& base_url, const std::optional<std::string>& title_id,
                           const std::optional<std::string>& icon) {
    if (icon && icons.reader_usable(*icon)) return base_url + "/icons/" + *icon + ".jpg";
    if (title_id && valid_title_id(*title_id) && icons.reader_published_path(*title_id))
        return base_url + "/icons/" + normalize_title_id(*title_id) + ".jpg";
    return "switch_logo";
}

}  // namespace relay
