#include <doctest/doctest.h>

#include <atomic>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <vector>

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

std::string read_file(const std::string& p) {
    std::ifstream f(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}

struct Env {
    fs::path root;
    std::unique_ptr<Db> db;
    int64_t clock = 1000;
    int fired = 0;
    std::string last_fired;
    std::unique_ptr<Icons> icons;

    explicit Env(int threshold = 2) {
        static std::atomic<int> n{0};
        root = fs::temp_directory_path() /
               ("relay_icons_test_" + std::to_string(::getpid()) + "_" + std::to_string(n++));
        fs::remove_all(root);
        fs::create_directories(root);
        db = Db::open((root / "t.db").string());
        icons = std::make_unique<Icons>(*db, (root / "icons").string(), threshold,
                                        [this] { return clock; });
        icons->on_published = [this](const std::string& t) {
            ++fired;
            last_fired = t;
        };
    }
    ~Env() {
        icons.reset();
        db.reset();
        fs::remove_all(root);
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

TEST_CASE("icons: consensus publishing") {
    Env e;
    auto jpg = make_jpeg(256, 256, 1);
    auto a = e.icons->submit(TID, jpg, "A", false);
    CHECK(a.result == IconResult::Pending);
    CHECK(a.votes == 1);
    CHECK(a.needed == 2);
    CHECK_FALSE(e.icons->published_path(TID));
    CHECK(e.fired == 0);

    auto b = e.icons->submit(TID, jpg, "B", false);
    CHECK(b.result == IconResult::Published);
    CHECK(e.fired == 1);
    CHECK(e.last_fired == TID);
    auto path = e.icons->published_path("0100a0d02127e000");
    REQUIRE(path);
    CHECK(fs::exists(*path));
    CHECK(fs::path(*path).filename() == "0100A0D02127E000.jpg");

    auto served = read_file(*path);
    CHECK(served != jpg);
    int w = 0, h = 0, c = 0;
    CHECK(stbi_info_from_memory(reinterpret_cast<const unsigned char*>(served.data()),
                                static_cast<int>(served.size()), &w, &h, &c));
    CHECK(w == 256);
    CHECK(h == 256);
}

TEST_CASE("icons: same user twice counts once") {
    Env e;
    auto jpg = make_jpeg(256, 256, 1);
    CHECK(e.icons->submit(TID, jpg, "A", false).result == IconResult::Pending);
    auto again = e.icons->submit(TID, jpg, "A", false);
    CHECK(again.result == IconResult::Pending);
    CHECK(again.votes == 1);
    CHECK(e.fired == 0);
}

TEST_CASE("icons: different bytes do not combine votes") {
    Env e;
    CHECK(e.icons->submit(TID, make_jpeg(256, 256, 1), "A", false).result == IconResult::Pending);
    auto o = e.icons->submit(TID, make_jpeg(256, 256, 2), "B", false);
    CHECK(o.result == IconResult::Pending);
    CHECK(o.votes == 1);
}

TEST_CASE("icons: admin publishes immediately and replaces") {
    Env e;
    auto one = make_jpeg(256, 256, 1);
    auto two = make_jpeg(256, 256, 2);
    CHECK(e.icons->submit(TID, one, "", true).result == IconResult::Published);
    CHECK(e.fired == 1);
    auto path = *e.icons->published_path(TID);
    auto before = read_file(path);

    CHECK(e.icons->submit(TID, two, "", true).result == IconResult::Published);
    CHECK(e.fired == 2);
    CHECK(read_file(path) != before);
}

TEST_CASE("icons: non-admin upload on a published title") {
    Env e;
    CHECK(e.icons->submit(TID, make_jpeg(256, 256, 1), "", true).result == IconResult::Published);
    auto two = make_jpeg(256, 256, 2);
    auto path = *e.icons->published_path(TID);
    auto before = read_file(path);

    auto o = e.icons->submit(TID, two, "A", false);
    CHECK(o.result == IconResult::AlreadyPublished);
    CHECK(read_file(path) == before);
    CHECK(e.fired == 1);
    // A recorded vote for `two` would make this probe return 2.
    CHECK(e.db->add_vote(TID, sha256_hex(two), "Z", e.clock) == 1);
}

TEST_CASE("icons: rejected uploads record no vote") {
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
    std::string huge(131073, 'x');
    auto small = make_jpeg(128, 128, 1);

    CHECK(e.icons->submit(TID, png, "A", false).result == IconResult::Invalid);
    CHECK(e.icons->submit(TID, big, "A", false).result == IconResult::Invalid);
    CHECK(e.icons->submit(TID, huge, "A", false).result == IconResult::TooLarge);
    CHECK(e.icons->submit(TID, small, "A", false).result == IconResult::Invalid);
    CHECK(e.icons->submit(TID, "", "A", false).result == IconResult::Invalid);
    CHECK(e.icons->submit(TID, "not an image", "A", false).result == IconResult::Invalid);

    CHECK(e.db->add_vote(TID, sha256_hex(png), "Z", 1) == 1);
    CHECK(e.db->add_vote(TID, sha256_hex(big), "Z", 1) == 1);
    CHECK(e.db->add_vote(TID, sha256_hex(huge), "Z", 1) == 1);
    CHECK_FALSE(e.icons->published_path(TID));
}

TEST_CASE("icons: size boundary and title id checks") {
    Env e;
    std::string exact(131072, 'x');
    CHECK(e.icons->submit(TID, exact, "A", false).result == IconResult::Invalid);
    std::string over(131073, 'x');
    CHECK(e.icons->submit(TID, over, "A", false).result == IconResult::TooLarge);
    auto jpg = make_jpeg(256, 256, 1);
    CHECK(e.icons->submit("0000000000000000", jpg, "A", true).result == IconResult::Invalid);
    CHECK(e.icons->submit("0000000000000000", over, "A", true).result == IconResult::Invalid);
    CHECK(e.fired == 0);
}

TEST_CASE("icons: admin_delete blocks the hash") {
    Env e;
    auto jpg = make_jpeg(256, 256, 1);
    CHECK_FALSE(e.icons->admin_delete(TID));
    CHECK(e.icons->submit(TID, jpg, "", true).result == IconResult::Published);
    auto path = *e.icons->published_path(TID);

    CHECK(e.icons->admin_delete(TID));
    CHECK_FALSE(e.icons->published_path(TID));
    CHECK_FALSE(fs::exists(path));
    CHECK_FALSE(e.icons->admin_delete(TID));

    CHECK(e.icons->submit(TID, jpg, "A", false).result == IconResult::Blocked);
    CHECK(e.icons->submit(TID, jpg, "", true).result == IconResult::Blocked);
    CHECK(e.icons->submit(TID, make_jpeg(256, 256, 2), "A", false).result == IconResult::Pending);
}

TEST_CASE("icons: published_path requires the file") {
    Env e;
    CHECK(e.icons->submit(TID, make_jpeg(256, 256, 1), "", true).result == IconResult::Published);
    fs::remove(*e.icons->published_path(TID));
    CHECK_FALSE(e.icons->published_path(TID));
    CHECK_FALSE(e.icons->published_path("bad"));
}

TEST_CASE("icons: works without on_published") {
    Env e;
    e.icons->on_published = nullptr;
    CHECK(e.icons->submit(TID, make_jpeg(256, 256, 1), "", true).result == IconResult::Published);
}

TEST_CASE("icons: write failure throws and publishes nothing") {
    if (::geteuid() == 0) return;
    Env e;
    auto jpg = make_jpeg(256, 256, 1);
    fs::permissions(e.root / "icons", fs::perms::owner_read | fs::perms::owner_exec);
    CHECK_THROWS_AS(e.icons->submit(TID, jpg, "", true), std::runtime_error);
    fs::permissions(e.root / "icons", fs::perms::owner_all);
    CHECK_FALSE(e.icons->published_path(TID));
    CHECK(e.fired == 0);
}

TEST_CASE("icons: admin_delete fires on_unpublished once, outside the lock") {
    Env e;
    std::vector<std::string> fired;
    e.icons->on_unpublished = [&](const std::string& t) {
        fired.push_back(t);
        CHECK_FALSE(e.icons->published_path(t));
    };
    CHECK_FALSE(e.icons->admin_delete(TID));
    CHECK(fired.empty());
    CHECK(e.icons->submit(TID, make_jpeg(256, 256, 1), "", true).result == IconResult::Published);
    CHECK(e.icons->admin_delete("0100a0d02127e000"));
    CHECK(fired == std::vector<std::string>{TID});
}
