// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

#include <doctest/doctest.h>

#include <atomic>
#include <chrono>
#include <exception>
#include <filesystem>
#include <functional>
#include <thread>
#include <utility>

#include <sqlite3.h>

// An HTTP-side write stuck behind the database write lock, as during a burst: a raw connection
// holds a write transaction for `hold`, and `write` (a Db or Icons write) runs on another thread,
// where it waits for that transaction while holding the relay's own locks.
class StuckWriter {
public:
    StuckWriter(const std::filesystem::path& db_path, std::function<void()> write,
                std::chrono::milliseconds hold = std::chrono::milliseconds(1000)) {
        REQUIRE(sqlite3_open(db_path.string().c_str(), &raw_) == SQLITE_OK);
        REQUIRE(sqlite3_exec(raw_, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr) == SQLITE_OK);
        holding_ = true;
        writer_ = std::thread([this, write = std::move(write)] {
            in_write_ = true;
            try {
                write();
            } catch (const std::exception&) {
            }
            // A write that returns while the transaction is still open never waited for it.
            if (holding_) returned_early_ = true;
            done_ = true;
        });
        holder_ = std::thread([this, hold] {
            std::this_thread::sleep_for(hold);
            // Cleared before the rollback, so that while it reads true the transaction is open.
            holding_ = false;
            sqlite3_exec(raw_, "ROLLBACK", nullptr, nullptr, nullptr);
        });
        // Lets the writer take its locks and reach SQLite's busy wait.
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    ~StuckWriter() { join(); }
    StuckWriter(const StuckWriter&) = delete;
    StuckWriter& operator=(const StuckWriter&) = delete;

    // The writer is inside `write` and the transaction it waits for is still open, so it is in
    // SQLite's busy wait with the relay's locks held, not merely not started or already done.
    bool waiting() const { return in_write_ && holding_ && !done_; }
    // After join(): `write` returned only once the transaction ended, so it really waited.
    bool was_blocked() const { return done_ && !returned_early_; }
    void join() {
        if (holder_.joinable()) holder_.join();
        if (writer_.joinable()) writer_.join();
        if (raw_) sqlite3_close(raw_);
        raw_ = nullptr;
    }

private:
    sqlite3* raw_ = nullptr;
    std::atomic<bool> in_write_{false}, holding_{false}, done_{false}, returned_early_{false};
    std::thread writer_, holder_;
};

// Milliseconds `f` takes.
template <class F>
long long elapsed_ms(F&& f) {
    const auto start = std::chrono::steady_clock::now();
    f();
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
}
