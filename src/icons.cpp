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

Icons::Icons(Db& db, std::string icons_dir, int threshold, std::function<int64_t()> now)
    : db_(db), dir_(std::move(icons_dir)), threshold_(threshold), now_(std::move(now)) {
    fs::create_directories(dir_);
}

std::string Icons::path_for(const std::string& tid) const {
    return (fs::path(dir_) / (tid + ".jpg")).string();
}

IconOutcome Icons::submit(std::string_view title_id, std::string_view jpeg,
                          std::string_view voter_discord_id, bool admin) {
    if (!valid_title_id(title_id)) return {IconResult::Invalid};
    if (jpeg.empty()) return {IconResult::Invalid};
    if (jpeg.size() > kMaxBytes) return {IconResult::TooLarge};
    auto encoded = reencode(jpeg);
    if (!encoded) return {IconResult::Invalid};

    const std::string tid = normalize_title_id(title_id);
    const std::string hash = sha256_hex(jpeg);
    {
        std::lock_guard lk(mu_);
        if (db_.is_blocked(hash)) return {IconResult::Blocked};
        const bool published = db_.published_icon(tid).has_value();
        if (published && !admin) return {IconResult::AlreadyPublished};

        int votes = 0;
        if (!admin) {
            votes = db_.add_vote(tid, hash, voter_discord_id, now_());
            if (votes < threshold_) return {IconResult::Pending, votes, threshold_};
        }
        if (!write_atomic(path_for(tid), *encoded))
            throw std::runtime_error("failed to write icon file");
        db_.publish_icon(tid, hash, now_());
    }
    if (on_published) on_published(tid);
    return {IconResult::Published};
}

std::optional<std::string> Icons::published_path(std::string_view title_id) {
    if (!valid_title_id(title_id)) return std::nullopt;
    const std::string tid = normalize_title_id(title_id);
    std::lock_guard lk(mu_);
    if (!db_.published_icon(tid)) return std::nullopt;
    auto p = path_for(tid);
    std::error_code ec;
    if (!fs::exists(p, ec)) return std::nullopt;
    return p;
}

bool Icons::admin_delete(std::string_view title_id) {
    if (!valid_title_id(title_id)) return false;
    const std::string tid = normalize_title_id(title_id);
    {
        std::lock_guard lk(mu_);
        auto rec = db_.published_icon(tid);
        if (!rec) return false;
        db_.unpublish_icon(tid);
        db_.block_hash(rec->sha256);
        std::error_code ec;
        fs::remove(path_for(tid), ec);
    }
    if (on_unpublished) on_unpublished(tid);
    return true;
}

}  // namespace relay
