// SPDX-License-Identifier: AGPL-3.0-or-later
#include "icon_store.hpp"

#include <filesystem>
#include <fstream>
#include <iterator>
#include <utility>

namespace relay {
namespace fs = std::filesystem;

DiskIconStore::DiskIconStore(std::string dir) : dir_(std::move(dir)) { fs::create_directories(fs::path(dir_) / "h"); }

std::string DiskIconStore::path(std::string_view key) const { return (fs::path(dir_) / key).string(); }

bool DiskIconStore::put(std::string_view key, std::string_view bytes) {
    const fs::path dest = path(key);
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

std::optional<std::string> DiskIconStore::get(std::string_view key) {
    std::ifstream f(path(key), std::ios::binary);
    if (!f) return std::nullopt;
    std::string bytes(std::istreambuf_iterator<char>(f), {});
    if (f.bad()) return std::nullopt;
    return bytes;
}

bool DiskIconStore::exists(std::string_view key) {
    std::error_code ec;
    return fs::exists(path(key), ec);
}

void DiskIconStore::remove(std::string_view key) {
    std::error_code ec;
    fs::remove(path(key), ec);
}

}  // namespace relay
