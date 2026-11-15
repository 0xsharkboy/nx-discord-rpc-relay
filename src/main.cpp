#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <mutex>
#include <pthread.h>
#include <signal.h>
#include <string>
#include <thread>
#include <unistd.h>
#include <variant>

#include <httplib.h>

#include "api.hpp"
#include "config.hpp"
#include "db.hpp"
#include "icons.hpp"
#include "links.hpp"
#include "oauth.hpp"
#include "presence.hpp"
#include "rate_limit.hpp"
#include "refresher.hpp"
#include "sdk_backend.hpp"
#include "version.hpp"

using namespace relay;
using namespace std::chrono_literals;

namespace {

constexpr int64_t kHourMs = 3'600'000;
constexpr int kLinkPerHour = 10;
constexpr int kPollPerHour = 720;
constexpr int kIconPerHour = 30;
constexpr auto kTickEvery = 10ms;
constexpr auto kRefreshEvery = 10min;
constexpr auto kExpireVotesEvery = 24h;
// How long an unlinked account's tokens may wait before their revocation is sent.
constexpr auto kRevokeEvery = 2s;
constexpr int64_t kVoteLifetimeS = 30 * 86400;
constexpr auto kClearDrain = 1500ms;
constexpr auto kDisconnectDrain = 500ms;

int64_t unix_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}
int64_t unix_s() { return unix_ms() / 1000; }

class StopFlag {
public:
    void set() {
        {
            std::lock_guard lk(mu_);
            stop_ = true;
        }
        cv_.notify_all();
    }
    bool is_set() {
        std::lock_guard lk(mu_);
        return stop_;
    }
    template <class D>
    void wait_for(D d) {
        std::unique_lock lk(mu_);
        cv_.wait_for(lk, d, [this] { return stop_; });
    }

private:
    std::mutex mu_;
    std::condition_variable cv_;
    bool stop_ = false;
};

void pump(IPresenceBackend& backend, std::chrono::milliseconds total) {
    const auto until = std::chrono::steady_clock::now() + total;
    while (std::chrono::steady_clock::now() < until) {
        backend.run_callbacks();
        std::this_thread::sleep_for(kTickEvery);
    }
}

void background_jobs(Refresher& refresher, Links& links, Db& db, StopFlag& stop) {
    auto next_refresh = std::chrono::steady_clock::now();
    auto next_expiry = next_refresh;
    while (!stop.is_set()) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= next_refresh) {
            refresher.run_once();
            next_refresh = now + kRefreshEvery;
        }
        if (now >= next_expiry) {
            try {
                db.expire_votes(unix_s() - kVoteLifetimeS);
            } catch (const std::exception& e) {
                std::cerr << "relay: vote expiry failed: " << e.what() << '\n';
            }
            next_expiry = now + kExpireVotesEvery;
        }
        links.flush_revocations();
        stop.wait_for(std::min({next_refresh - std::chrono::steady_clock::now(),
                                next_expiry - std::chrono::steady_clock::now(),
                                std::chrono::steady_clock::duration(kRevokeEvery)}));
    }
}

}  // namespace

int main() {
    std::signal(SIGPIPE, SIG_IGN);

    auto loaded = load_config([](const char* name) -> std::optional<std::string> {
        const char* v = std::getenv(name);
        if (!v) return std::nullopt;
        return std::string(v);
    });
    if (auto* err = std::get_if<std::string>(&loaded)) {
        std::cerr << "relay: invalid configuration: " << *err << '\n';
        return 2;
    }
    const Config cfg = std::get<Config>(std::move(loaded));

    uint64_t application_id = 0;
    try {
        application_id = std::stoull(cfg.client_id);
    } catch (const std::exception&) {
        std::cerr << "relay: invalid configuration: DISCORD_CLIENT_ID is out of range\n";
        return 2;
    }

    // Blocked before any thread starts so that every thread inherits the mask and only the
    // watcher's sigwait receives them.
    sigset_t signals;
    sigemptyset(&signals);
    sigaddset(&signals, SIGTERM);
    sigaddset(&signals, SIGINT);
    pthread_sigmask(SIG_BLOCK, &signals, nullptr);

    const std::filesystem::path data_dir(cfg.data_dir);
    const auto icons_dir = data_dir / "icons";
    std::unique_ptr<Db> db;
    try {
        std::filesystem::create_directories(icons_dir);
        db = Db::open((data_dir / "relay.db").string());
    } catch (const std::exception& e) {
        std::cerr << "relay: cannot prepare the data directory: " << e.what() << '\n';
        return 1;
    }

    // The main thread is the SDK thread: the backend and Presence are built, ticked and destroyed
    // here, Presence first.
    SdkBackend backend(application_id);
    DiscordOAuth oauth(cfg);
    Icons icons(*db, icons_dir.string(), cfg.publish_threshold, unix_s);
    Presence presence(
        backend, *db, cfg.token_key, cfg.public_base_url,
        [&icons](const std::string& tid) { return icons.published_path(tid).has_value(); }, unix_ms);
    icons.on_published = [&presence](const std::string& tid) { presence.icon_published(tid); };
    icons.on_unpublished = [&presence](const std::string& tid) { presence.icon_published(tid); };
    Links links(oauth, *db, cfg.token_key, unix_ms);
    links.on_relinked = [&presence](const std::string& id) { presence.drop(id); };
    Refresher refresher(oauth, *db, cfg.token_key, presence, unix_s);

    RateLimiter link_limiter(kLinkPerHour, kHourMs, unix_ms);
    RateLimiter poll_limiter(kPollPerHour, kHourMs, unix_ms);
    RateLimiter icon_limiter(kIconPerHour, kHourMs, unix_ms);
    Deps deps{cfg, *db, icons, links, presence, link_limiter, poll_limiter, icon_limiter, nullptr, nullptr};

    httplib::Server svr;
    register_routes(svr, deps);
    if (!svr.bind_to_port(cfg.listen_host, cfg.listen_port)) {
        std::cerr << "relay: cannot listen on " << cfg.listen_host << ':' << cfg.listen_port << '\n';
        return 1;
    }
    std::cout << "relay " << version() << " listening on " << cfg.listen_host << ':' << cfg.listen_port
              << std::endl;

    StopFlag stop;
    std::atomic<bool> listen_failed{false}, http_done{false}, jobs_done{false};

    std::thread watcher([&] {
        int sig = 0;
        sigwait(&signals, &sig);
        stop.set();
        // A stop() issued before listen_after_bind() marks the server running would be lost. Not
        // wait_until_ready(): it spins forever when the accept loop has already failed.
        while (!http_done && !svr.is_running()) std::this_thread::sleep_for(1ms);
        if (!http_done) svr.stop();
    });

    std::thread http([&] {
        svr.listen_after_bind();
        const bool unexpected = !stop.is_set();
        http_done = true;
        if (unexpected) {
            listen_failed = true;
            std::cerr << "relay: the HTTP server stopped unexpectedly\n";
            ::kill(::getpid(), SIGTERM);
        }
    });

    std::thread jobs([&] {
        background_jobs(refresher, links, *db, stop);
        jobs_done = true;
    });

    // Ticking continues until in-flight requests and a running refresh are done, so the SDK keeps
    // being pumped while they finish.
    bool announced = false;
    while (!stop.is_set() || !http_done || !jobs_done) {
        if (stop.is_set() && !announced) {
            std::cout << "relay: shutting down" << std::endl;
            announced = true;
        }
        try {
            presence.tick();
        } catch (const std::exception& e) {
            std::cerr << "relay: presence tick failed: " << e.what() << '\n';
        } catch (...) {
            std::cerr << "relay: presence tick failed\n";
        }
        if (announced)
            std::this_thread::sleep_for(kTickEvery);
        else
            stop.wait_for(kTickEvery);
    }

    watcher.join();
    http.join();
    jobs.join();

    // No request handler runs anymore, so nothing can enqueue behind the clears.
    try {
        presence.clear_all();
        pump(backend, kClearDrain);
        presence.disconnect_all();
        pump(backend, kDisconnectDrain);
    } catch (const std::exception& e) {
        std::cerr << "relay: shutdown cleanup failed: " << e.what() << '\n';
    }
    return listen_failed ? 1 : 0;
}
