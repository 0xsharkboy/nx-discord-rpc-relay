// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace relay {

// Where icon bytes live, by key ("h/<sha256>.jpg" for stored icons, "<TITLE_ID>.jpg" for legacy
// ones). Keys are built by Icons from validated names only. Every method may be called from several
// threads at once.
class IconStore {
public:
    virtual ~IconStore() = default;
    // Replaces the object atomically: a reader sees the old bytes or the new ones, never a part.
    // False on failure, with nothing written.
    virtual bool put(std::string_view key, std::string_view bytes) = 0;
    // Nothing when the object is missing or cannot be read.
    virtual std::optional<std::string> get(std::string_view key) = 0;
    virtual bool exists(std::string_view key) = 0;
    // Missing objects and failures are ignored: a leftover object is only wasted space.
    virtual void remove(std::string_view key) = 0;
};

// Objects as files under a directory, the key being the relative path.
class DiskIconStore final : public IconStore {
public:
    // Creates the directory and its "h" subdirectory. Throws std::filesystem::filesystem_error.
    explicit DiskIconStore(std::string dir);

    bool put(std::string_view key, std::string_view bytes) override;
    std::optional<std::string> get(std::string_view key) override;
    bool exists(std::string_view key) override;
    void remove(std::string_view key) override;

private:
    std::string path(std::string_view key) const;

    std::string dir_;
};

}  // namespace relay
