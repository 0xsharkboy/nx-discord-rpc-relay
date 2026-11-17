// SPDX-License-Identifier: AGPL-3.0-or-later
#include <doctest/doctest.h>

#include <atomic>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <vector>

#include <sqlite3.h>
#include <stb_image.h>
#include <stb_image_write.h>

#include "crypto.hpp"
#include "icons.hpp"

using namespace relay;
namespace fs = std::filesystem;

namespace {

void append_cb(void* ctx, void* data, int size) {
    static_cast<std::string*>(ctx)->append(static_cast<const char*>(data), size);
}

std::string make_jpeg(int w, int h, int seed) {
    std::vector<unsigned char> px(static_cast<size_t>(w) * h * 3);
    for (int y = 0; y < h; ++y)
        for (int x = 0; x < w; ++x) {
            unsigned char* p = &px[(static_cast<size_t>(y) * w + x) * 3];
            p[0] = static_cast<unsigned char>(seed * 40 + (x * 255 / w) / 4);
            p[1] = static_cast<unsigned char>((y * 255 / h) / 4);
            p[2] = static_cast<unsigned char>(seed * 20);
        }
    std::string out;
    stbi_write_jpg_to_func(append_cb, &out, w, h, 3, px.data(), 95);
    return out;
}

// stb cannot emit a real 4096x4096 JPEG under the size cap, so patch the SOF0 dimensions of a
// small one: the header check must reject it before any pixel decode.
std::string make_oversized_header_jpeg() {
    auto jpg = make_jpeg(256, 256, 1);
    for (size_t i = 0; i + 9 < jpg.size(); ++i) {
        if (static_cast<unsigned char>(jpg[i]) == 0xFF && static_cast<unsigned char>(jpg[i + 1]) == 0xC0) {
            for (size_t k : {i + 5, i + 7}) {
                jpg[k] = 0x10;
                jpg[k + 1] = 0x00;
            }
            break;
        }
    }
    return jpg;
}

std::string make_png(int w, int h) {
    std::vector<unsigned char> px(static_cast<size_t>(w) * h * 3, 120);
    std::string out;
    stbi_write_png_to_func(append_cb, &out, w, h, 3, px.data(), w * 3);
    return out;
}

std::string read_file(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}

void write_file(const fs::path& p, const std::string& bytes) {
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    f << bytes;
}

size_t count_files(const fs::path& dir) {
    size_t n = 0;
    for (const auto& e : fs::directory_iterator(dir))
        if (e.is_regular_file()) ++n;
    return n;
}

struct Env {
    fs::path root;
    std::unique_ptr<Db> db;
    int64_t clock = 1000;
    std::unique_ptr<Icons> icons;

    explicit Env(int64_t max_files = kDefaultMaxIconFiles) {
        static std::atomic<int> n{0};
        root = fs::temp_directory_path() /
               ("relay_icons_test_" + std::to_string(::getpid()) + "_" + std::to_string(n++));
        fs::remove_all(root);
        fs::create_directories(root);
        db = Db::open((root / "t.db").string());
        icons = std::make_unique<Icons>(*db, (root / "icons").string(), max_files, [this] { return clock; });
    }
    ~Env() {
        icons.reset();
        db.reset();
        fs::remove_all(root);
    }
    fs::path hash_file(const std::string& sha) const { return root / "icons" / "h" / (sha + ".jpg"); }
    // A title icon published before v0.4.0: its row (no Db function writes one any more) and file.
    void seed_legacy(const std::string& tid, const std::string& sha) {
        sqlite3* raw = nullptr;
        REQUIRE(sqlite3_open((root / "t.db").string().c_str(), &raw) == SQLITE_OK);
        const std::string sql = "INSERT INTO published_icons VALUES ('" + tid + "', '" + sha + "', 1)";
        const int rc = sqlite3_exec(raw, sql.c_str(), nullptr, nullptr, nullptr);
        sqlite3_close(raw);
        REQUIRE(rc == SQLITE_OK);
        write_file(root / "icons" / (tid + ".jpg"), make_jpeg(256, 256, 3));
    }
};

const char* TID = "0100A0D02127E000";
}  // namespace

TEST_CASE("valid_title_id") {
    CHECK(valid_title_id("0100A0D02127E000"));
    CHECK(valid_title_id("0100a0d02127e000"));
    CHECK(valid_title_id("0500000000000001"));
    CHECK(valid_title_id("0100000000010000"));
    CHECK_FALSE(valid_title_id("0100000000000352"));
    CHECK_FALSE(valid_title_id("0000000000000000"));
    CHECK_FALSE(valid_title_id("0100A0D02127E00"));
    CHECK_FALSE(valid_title_id("0100A0D02127E0000"));
    CHECK_FALSE(valid_title_id("0100A0D02127E00G"));
    CHECK_FALSE(valid_title_id(""));
    CHECK(normalize_title_id("0100a0d02127e000") == "0100A0D02127E000");
}

TEST_CASE("icons: valid_sha256") {
    const std::string ok(64, 'a');
    CHECK(Icons::valid_sha256(ok));
    CHECK(Icons::valid_sha256(sha256_hex("x")));
    CHECK(Icons::valid_sha256("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    CHECK_FALSE(Icons::valid_sha256(std::string(63, 'a')));
    CHECK_FALSE(Icons::valid_sha256(std::string(65, 'a')));
    CHECK_FALSE(Icons::valid_sha256(std::string(64, 'A')));
    CHECK_FALSE(Icons::valid_sha256(std::string(63, 'a') + "g"));
    CHECK_FALSE(Icons::valid_sha256(std::string(63, 'a') + "/"));
    CHECK_FALSE(Icons::valid_sha256(""));
    CHECK(kDefaultMaxIconFiles == 10000);
    CHECK(kIconLifetimeS == 30 * 86400);
}

TEST_CASE("icons: store_names_file_after_raw_hash") {
    Env e;
    auto jpg = make_jpeg(256, 256, 1);
    const auto sha = sha256_hex(jpg);
    auto out = e.icons->store(jpg);
    CHECK(out.result == StoreResult::Stored);
    CHECK(out.sha256 == sha);
    REQUIRE(fs::exists(e.hash_file(sha)));
    CHECK(e.db->has_icon_file(sha));

    // The file holds the re-encoded image but keeps the name of the raw upload's hash.
    auto served = read_file(e.hash_file(sha));
    CHECK(served != jpg);
    int w = 0, h = 0, c = 0;
    CHECK(stbi_info_from_memory(reinterpret_cast<const unsigned char*>(served.data()),
                                static_cast<int>(served.size()), &w, &h, &c));
    CHECK(w == 256);
    CHECK(h == 256);

    CHECK(e.icons->usable(sha));
    auto path = e.icons->hash_path(sha);
    REQUIRE(path);
    CHECK(fs::path(*path) == e.hash_file(sha));
}

TEST_CASE("icons: store_same_bytes_twice_keeps_one_file") {
    Env e;
    auto jpg = make_jpeg(256, 256, 1);
    const auto sha = sha256_hex(jpg);
    REQUIRE(e.icons->store(jpg).result == StoreResult::Stored);
    // A second store of known bytes does not rewrite the file.
    write_file(e.hash_file(sha), "marker");
    e.clock += 50;
    auto again = e.icons->store(jpg);
    CHECK(again.result == StoreResult::Stored);
    CHECK(again.sha256 == sha);
    CHECK(read_file(e.hash_file(sha)) == "marker");
    CHECK(e.db->icon_file_count() == 1);
    CHECK(count_files(e.root / "icons" / "h") == 1);

    // A file that went missing behind a known row is written again.
    fs::remove(e.hash_file(sha));
    CHECK(e.icons->store(jpg).result == StoreResult::Stored);
    CHECK(fs::exists(e.hash_file(sha)));
    CHECK(e.db->icon_file_count() == 1);
}

TEST_CASE("icons: store_blocked_hash_is_refused") {
    Env e;
    auto jpg = make_jpeg(256, 256, 1);
    const auto sha = sha256_hex(jpg);
    e.db->block_hash(sha);
    auto out = e.icons->store(jpg);
    CHECK(out.result == StoreResult::Blocked);
    CHECK(out.sha256.empty());
    CHECK_FALSE(fs::exists(e.hash_file(sha)));
    CHECK_FALSE(e.db->has_icon_file(sha));
    CHECK_FALSE(e.icons->usable(sha));
}

TEST_CASE("icons: store_over_cap_is_full") {
    Env e(1);
    auto one = make_jpeg(256, 256, 1);
    auto two = make_jpeg(256, 256, 2);
    REQUIRE(e.icons->store(one).result == StoreResult::Stored);
    auto full = e.icons->store(two);
    CHECK(full.result == StoreResult::Full);
    CHECK(full.sha256.empty());
    CHECK_FALSE(fs::exists(e.hash_file(sha256_hex(two))));
    CHECK(e.db->icon_file_count() == 1);
    // Known bytes are still accepted at the cap.
    CHECK(e.icons->store(one).result == StoreResult::Stored);
}

TEST_CASE("icons: rejected uploads store nothing") {
    Env e;
    auto png = make_png(256, 256);
    auto big = make_oversized_header_jpeg();
    {
        int w = 0, h = 0, c = 0;
        REQUIRE(stbi_info_from_memory(reinterpret_cast<const unsigned char*>(big.data()),
                                      static_cast<int>(big.size()), &w, &h, &c));
        REQUIRE(w == 4096);
        REQUIRE(h == 4096);
    }
    REQUIRE(big.size() <= 131072);

    CHECK(e.icons->store(png).result == StoreResult::Invalid);
    CHECK(e.icons->store(big).result == StoreResult::Invalid);
    CHECK(e.icons->store(make_jpeg(128, 128, 1)).result == StoreResult::Invalid);
    CHECK(e.icons->store("").result == StoreResult::Invalid);
    CHECK(e.icons->store("not an image").result == StoreResult::Invalid);
    CHECK(e.icons->store(std::string(131072, 'x')).result == StoreResult::Invalid);
    CHECK(e.icons->store(std::string(131073, 'x')).result == StoreResult::TooLarge);
    CHECK(e.db->icon_file_count() == 0);
    CHECK(fs::is_empty(e.root / "icons" / "h"));
}

TEST_CASE("icons: usable and hash_path") {
    Env e;
    const std::string unknown(64, 'a');
    CHECK_FALSE(e.icons->usable(unknown));
    CHECK_FALSE(e.icons->hash_path(unknown));
    CHECK_FALSE(e.icons->usable("../t"));
    CHECK_FALSE(e.icons->hash_path("../t"));

    auto jpg = make_jpeg(256, 256, 1);
    const auto sha = e.icons->store(jpg).sha256;
    REQUIRE(e.icons->hash_path(sha));
    fs::remove(e.hash_file(sha));
    CHECK_FALSE(e.icons->hash_path(sha));
}

TEST_CASE("icons: touch writes at most once a day per hash") {
    Env e;
    const auto sha = e.icons->store(make_jpeg(256, 256, 1)).sha256;
    REQUIRE(e.db->icon_files_unused_since(1001) == std::vector<std::string>{sha});

    e.clock = 2000;
    e.icons->touch(sha);
    CHECK(e.db->icon_files_unused_since(2000).empty());
    CHECK(e.db->icon_files_unused_since(2001) == std::vector<std::string>{sha});

    e.clock = 2000 + 86399;
    e.icons->touch(sha);
    CHECK(e.db->icon_files_unused_since(2001) == std::vector<std::string>{sha});

    e.clock = 2000 + 86400;
    e.icons->touch(sha);
    CHECK(e.db->icon_files_unused_since(2000 + 86400).empty());

    // An invalid hash creates no row and leaves the stored one alone.
    e.clock += 2 * 86400;
    e.icons->touch("../t");
    CHECK_FALSE(e.db->has_icon_file("../t"));
    CHECK(e.db->icon_file_count() == 1);
    CHECK(e.db->icon_files_unused_since(2000 + 86401) == std::vector<std::string>{sha});
}

TEST_CASE("icons: cleanup_spares_in_use_and_recent") {
    Env e;
    const auto a = e.icons->store(make_jpeg(256, 256, 1)).sha256;
    const auto b = e.icons->store(make_jpeg(256, 256, 2)).sha256;
    e.clock += kIconLifetimeS - 10;
    const auto c = e.icons->store(make_jpeg(256, 256, 3)).sha256;
    e.clock += 20;

    CHECK(e.icons->cleanup({a}) == 1);
    CHECK(e.icons->usable(a));
    CHECK(fs::exists(e.hash_file(a)));
    CHECK_FALSE(e.icons->usable(b));
    CHECK_FALSE(e.db->has_icon_file(b));
    CHECK_FALSE(fs::exists(e.hash_file(b)));
    CHECK(e.icons->usable(c));
    CHECK(fs::exists(e.hash_file(c)));
    // A removed hash is not blocked: it can be stored again.
    CHECK_FALSE(e.db->is_blocked(b));
    CHECK(e.icons->store(make_jpeg(256, 256, 2)).result == StoreResult::Stored);

    CHECK(e.icons->cleanup({}) == 1);
    CHECK_FALSE(e.icons->usable(a));
}

TEST_CASE("icons: remove_hash_blocks_and_deletes") {
    Env e;
    auto jpg = make_jpeg(256, 256, 1);
    const auto sha = e.icons->store(jpg).sha256;
    CHECK(e.icons->remove_hash(sha));
    CHECK(e.db->is_blocked(sha));
    CHECK_FALSE(e.db->has_icon_file(sha));
    CHECK_FALSE(fs::exists(e.hash_file(sha)));
    CHECK_FALSE(e.icons->usable(sha));
    CHECK_FALSE(e.icons->hash_path(sha));
    CHECK(e.icons->store(jpg).result == StoreResult::Blocked);
    CHECK_FALSE(e.icons->remove_hash(sha));

    // A hash never stored can be blocked ahead of time.
    const std::string later(64, 'b');
    CHECK(e.icons->remove_hash(later));
    CHECK(e.db->is_blocked(later));
    CHECK_FALSE(e.icons->remove_hash(later));

    CHECK_FALSE(e.icons->remove_hash("../t"));
    CHECK_FALSE(e.db->is_blocked("../t"));
}

TEST_CASE("icons: a blocked hash with a leftover row is not usable") {
    Env e;
    const auto sha = e.icons->store(make_jpeg(256, 256, 1)).sha256;
    e.db->block_hash(sha);
    CHECK_FALSE(e.icons->usable(sha));
    CHECK_FALSE(e.icons->hash_path(sha));
}

TEST_CASE("icons: write failure throws and stores nothing") {
    if (::geteuid() == 0) return;
    Env e;
    auto jpg = make_jpeg(256, 256, 1);
    fs::permissions(e.root / "icons" / "h", fs::perms::owner_read | fs::perms::owner_exec);
    CHECK_THROWS_AS(e.icons->store(jpg), std::runtime_error);
    fs::permissions(e.root / "icons" / "h", fs::perms::owner_all);
    CHECK_FALSE(e.db->has_icon_file(sha256_hex(jpg)));
}

TEST_CASE("icons: legacy published_path requires row and file") {
    Env e;
    CHECK_FALSE(e.icons->published_path(TID));
    e.seed_legacy(TID, "H1");
    auto path = e.icons->published_path("0100a0d02127e000");
    REQUIRE(path);
    CHECK(fs::path(*path).filename() == "0100A0D02127E000.jpg");
    fs::remove(*path);
    CHECK_FALSE(e.icons->published_path(TID));
    CHECK_FALSE(e.icons->published_path("bad"));
}

TEST_CASE("icons: legacy admin_delete blocks the hash") {
    Env e;
    CHECK_FALSE(e.icons->admin_delete(TID));
    e.seed_legacy(TID, "H1");
    auto path = *e.icons->published_path(TID);
    CHECK(e.icons->admin_delete("0100a0d02127e000"));
    CHECK_FALSE(e.icons->published_path(TID));
    CHECK_FALSE(fs::exists(path));
    CHECK(e.db->is_blocked("H1"));
    CHECK_FALSE(e.icons->admin_delete(TID));
}

TEST_CASE("icons: a legacy title icon whose hash is blocked is not served") {
    Env e;
    const std::string sha(64, 'a');
    e.seed_legacy(TID, sha);
    REQUIRE(e.icons->published_path(TID));
    CHECK(e.icons->remove_hash(sha));
    CHECK_FALSE(e.icons->published_path(TID));
    CHECK(presence_image(*e.icons, "https://x.test", std::string(TID), std::nullopt) == "switch_logo");
}

TEST_CASE("icons: presence_image prefers a usable hash, then the legacy title icon, then the logo") {
    Env e;
    const auto jpg = make_jpeg(256, 256, 1);
    const auto sha = sha256_hex(jpg);
    const std::optional<std::string> tid = std::string(TID);
    const std::optional<std::string> none;
    CHECK(presence_image(*e.icons, "https://x.test", none, none) == "switch_logo");
    CHECK(presence_image(*e.icons, "https://x.test", tid, sha) == "switch_logo");
    e.seed_legacy(TID, std::string(64, 'b'));
    const std::string legacy = std::string("https://x.test/icons/") + TID + ".jpg";
    CHECK(presence_image(*e.icons, "https://x.test", tid, none) == legacy);
    CHECK(presence_image(*e.icons, "https://x.test", tid, sha) == legacy);
    REQUIRE(e.icons->store(jpg).result == StoreResult::Stored);
    const std::string hashed = "https://x.test/icons/" + sha + ".jpg";
    CHECK(presence_image(*e.icons, "https://x.test", tid, sha) == hashed);
    CHECK(presence_image(*e.icons, "https://x.test", none, sha) == hashed);
    e.icons->remove_hash(sha);
    CHECK(presence_image(*e.icons, "https://x.test", tid, sha) == legacy);
}
