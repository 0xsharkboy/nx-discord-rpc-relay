// SPDX-License-Identifier: AGPL-3.0-or-later
#include <doctest/doctest.h>

#include <atomic>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <unordered_map>
#include <vector>

#include <sqlite3.h>
#include <stb_image.h>
#include <stb_image_write.h>

#include "crypto.hpp"
#include "icons.hpp"
#include "stuck_writer.hpp"

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
    std::unique_ptr<DiskIconStore> store;
    std::unique_ptr<Icons> icons;

    explicit Env(int64_t max_files = kDefaultMaxIconFiles) {
        static std::atomic<int> n{0};
        root = fs::temp_directory_path() /
               ("relay_icons_test_" + std::to_string(::getpid()) + "_" + std::to_string(n++));
        fs::remove_all(root);
        fs::create_directories(root);
        db = Db::open((root / "t.db").string());
        store = std::make_unique<DiskIconStore>((root / "icons").string());
        icons = std::make_unique<Icons>(*db, *store, max_files, [this] { return clock; });
    }
    ~Env() {
        icons.reset();
        store.reset();
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
    auto bytes = e.icons->hash_bytes(sha);
    REQUIRE(bytes);
    CHECK(*bytes == served);
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

TEST_CASE("icons: usable and hash_bytes") {
    Env e;
    const std::string unknown(64, 'a');
    CHECK_FALSE(e.icons->usable(unknown));
    CHECK_FALSE(e.icons->hash_bytes(unknown));
    CHECK_FALSE(e.icons->usable("../t"));
    CHECK_FALSE(e.icons->hash_bytes("../t"));

    auto jpg = make_jpeg(256, 256, 1);
    const auto sha = e.icons->store(jpg).sha256;
    REQUIRE(e.icons->hash_bytes(sha));
    fs::remove(e.hash_file(sha));
    CHECK_FALSE(e.icons->hash_bytes(sha));
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

// The row goes before the file, so a reader never finds a usable row whose file is gone.
TEST_CASE("icons: cleanup keeps the file when its row cannot be deleted") {
    Env e;
    const auto a = e.icons->store(make_jpeg(256, 256, 1)).sha256;
    e.clock += kIconLifetimeS + 10;
    sqlite3* raw = nullptr;
    REQUIRE(sqlite3_open((e.root / "t.db").string().c_str(), &raw) == SQLITE_OK);
    const int rc = sqlite3_exec(raw,
                                "CREATE TRIGGER no_delete BEFORE DELETE ON icon_files "
                                "BEGIN SELECT RAISE(ABORT, 'no delete'); END",
                                nullptr, nullptr, nullptr);
    sqlite3_close(raw);
    REQUIRE(rc == SQLITE_OK);

    CHECK_THROWS(e.icons->cleanup({}));
    CHECK(e.icons->usable(a));
    CHECK(fs::exists(e.hash_file(a)));
    CHECK(e.icons->hash_bytes(a));
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
    CHECK_FALSE(e.icons->hash_bytes(sha));
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
    CHECK_FALSE(e.icons->hash_bytes(sha));
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

TEST_CASE("icons: legacy published_bytes requires row and file") {
    Env e;
    CHECK_FALSE(e.icons->published_bytes(TID));
    e.seed_legacy(TID, "H1");
    const auto path = e.root / "icons" / "0100A0D02127E000.jpg";
    auto bytes = e.icons->published_bytes("0100a0d02127e000");
    REQUIRE(bytes);
    CHECK(*bytes == read_file(path));
    fs::remove(path);
    CHECK_FALSE(e.icons->published_bytes(TID));
    CHECK_FALSE(e.icons->published_bytes("bad"));
}

TEST_CASE("icons: legacy admin_delete blocks the hash") {
    Env e;
    CHECK_FALSE(e.icons->admin_delete(TID));
    e.seed_legacy(TID, "H1");
    const auto path = e.root / "icons" / (std::string(TID) + ".jpg");
    REQUIRE(e.icons->published_bytes(TID));
    CHECK(e.icons->admin_delete("0100a0d02127e000"));
    CHECK_FALSE(e.icons->published_bytes(TID));
    CHECK_FALSE(fs::exists(path));
    CHECK(e.db->is_blocked("H1"));
    CHECK_FALSE(e.icons->admin_delete(TID));
}

TEST_CASE("icons: a legacy title icon whose hash is blocked is not served") {
    Env e;
    const std::string sha(64, 'a');
    e.seed_legacy(TID, sha);
    REQUIRE(e.icons->published_bytes(TID));
    CHECK(e.icons->remove_hash(sha));
    CHECK_FALSE(e.icons->published_bytes(TID));
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

TEST_CASE("icons: sdk_reads_do_not_wait_for_writer") {
    Env e;
    const auto sha = e.icons->store(make_jpeg(256, 256, 1)).sha256;
    REQUIRE(Icons::valid_sha256(sha));
    e.seed_legacy(TID, std::string(64, 'b'));
    const std::optional<std::string> tid = std::string(TID);
    // An HTTP worker recording a use holds the Icons lock while it waits for the database.
    StuckWriter w(e.root / "t.db", [&] { e.icons->touch(sha); });
    std::string hashed, legacy;
    const auto ms = elapsed_ms([&] {
        hashed = presence_image(*e.icons, "https://x.test", tid, sha);
        legacy = presence_image(*e.icons, "https://x.test", tid, std::nullopt);
    });
    const bool writer_was_waiting = w.waiting();
    w.join();
    CHECK(w.was_blocked());
    CHECK(writer_was_waiting);
    CHECK(ms < 500);  // writer holds for 1 s; slack keeps loaded hosts green
    CHECK(hashed == "https://x.test/icons/" + sha + ".jpg");
    CHECK(legacy == std::string("https://x.test/icons/") + TID + ".jpg");
}

TEST_CASE("icons: the reader lookups answer like usable and published_bytes") {
    Env e;
    const std::string unknown(64, 'a');
    const auto sha = e.icons->store(make_jpeg(256, 256, 1)).sha256;
    const auto same = [&](const std::string& h) { return e.icons->reader_usable(h) == e.icons->usable(h); };
    const auto same_published = [&](const std::string& t) {
        return e.icons->reader_published(t) == e.icons->published_bytes(t).has_value();
    };
    CHECK(same(unknown));
    CHECK(same("../t"));
    CHECK(e.icons->reader_usable(sha));
    CHECK(same(sha));
    CHECK_FALSE(e.icons->reader_published(TID));
    CHECK(same_published(TID));
    e.seed_legacy(TID, unknown);
    CHECK(e.icons->reader_published("0100a0d02127e000"));
    CHECK(same_published("0100a0d02127e000"));
    CHECK(same_published("bad"));
    CHECK_FALSE(e.icons->reader_published("bad"));
    // A legacy title icon whose file is gone is not served.
    const auto path = (e.root / "icons" / (std::string(TID) + ".jpg")).string();
    fs::rename(path, path + ".bak");
    CHECK_FALSE(e.icons->reader_published(TID));
    fs::rename(path + ".bak", path);
    REQUIRE(e.icons->reader_published(TID));
    // Blocking hides both the hash and a legacy icon with the same bytes.
    e.icons->remove_hash(sha);
    CHECK_FALSE(e.icons->reader_usable(sha));
    CHECK(same(sha));
    e.icons->remove_hash(unknown);
    CHECK_FALSE(e.icons->reader_published(TID));
    CHECK(same_published(TID));
}

TEST_CASE("icon store: disk objects are written, read, checked and removed by key") {
    Env e;
    DiskIconStore& s = *e.store;
    const std::string key = "h/" + std::string(64, 'b') + ".jpg";
    CHECK_FALSE(s.exists(key));
    CHECK_FALSE(s.get(key));
    REQUIRE(s.put(key, "one"));
    CHECK(s.exists(key));
    CHECK(read_file(e.root / "icons" / key) == "one");
    REQUIRE(s.put(key, "two"));
    CHECK(*s.get(key) == "two");
    CHECK_FALSE(fs::exists(e.root / "icons" / (key + ".tmp")));
    s.remove(key);
    CHECK_FALSE(s.exists(key));
    s.remove(key);
    CHECK_FALSE(s.put("missing/dir.jpg", "x"));
}

namespace {

// Objects in memory: Icons must work on any store, not only on files.
struct MemoryStore final : IconStore {
    std::mutex mu;
    std::unordered_map<std::string, std::string> objects;
    bool fail_puts = false;

    bool put(std::string_view key, std::string_view bytes) override {
        std::lock_guard lk(mu);
        if (fail_puts) return false;
        objects[std::string(key)] = std::string(bytes);
        return true;
    }
    std::optional<std::string> get(std::string_view key) override {
        std::lock_guard lk(mu);
        auto it = objects.find(std::string(key));
        if (it == objects.end()) return std::nullopt;
        return it->second;
    }
    bool exists(std::string_view key) override {
        std::lock_guard lk(mu);
        return objects.contains(std::string(key));
    }
    void remove(std::string_view key) override {
        std::lock_guard lk(mu);
        objects.erase(std::string(key));
    }
};

}  // namespace

TEST_CASE("icons: work on a store that is not the disk") {
    Env e;
    MemoryStore mem;
    Icons icons(*e.db, mem, kDefaultMaxIconFiles, [&e] { return e.clock; });
    const auto jpg = make_jpeg(256, 256, 1);
    const auto sha = sha256_hex(jpg);

    mem.fail_puts = true;
    CHECK_THROWS_AS(icons.store(jpg), std::runtime_error);
    CHECK_FALSE(e.db->has_icon_file(sha));
    mem.fail_puts = false;

    REQUIRE(icons.store(jpg).result == StoreResult::Stored);
    REQUIRE(mem.objects.contains("h/" + sha + ".jpg"));
    CHECK(fs::is_empty(e.root / "icons" / "h"));
    CHECK(icons.hash_bytes(sha) == mem.objects["h/" + sha + ".jpg"]);
    CHECK(presence_image(icons, "https://x.test", std::nullopt, sha) == "https://x.test/icons/" + sha + ".jpg");

    // A missing object is written again for known bytes.
    mem.objects.clear();
    CHECK_FALSE(icons.hash_bytes(sha));
    REQUIRE(icons.store(jpg).result == StoreResult::Stored);
    CHECK(icons.hash_bytes(sha));

    e.clock += kIconLifetimeS + 1;
    CHECK(icons.cleanup({}) == 1);
    CHECK(mem.objects.empty());
}
