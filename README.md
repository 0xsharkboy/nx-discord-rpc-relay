# nx-discord-rpc relay

Relay server for nx-discord-rpc. It sets Discord Rich Presence on behalf of linked users through the official Discord Social SDK, so the Nintendo Switch homebrew never handles a Discord token.

This repository is private: it contains the Discord Social SDK binary.

## Build

Everything comes from the Nix flake.

    nix develop -c cmake -B build -G Ninja
    nix develop -c cmake --build build
    nix develop -c ctest --test-dir build --output-on-failure
