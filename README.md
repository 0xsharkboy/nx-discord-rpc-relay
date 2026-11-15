# nx-discord-rpc relay

Relay server for nx-discord-rpc. It sets Discord Rich Presence on behalf of linked users through the official Discord Social SDK, so the Nintendo Switch homebrew never handles a Discord token.

This repository is private: it contains the Discord Social SDK binary.

## Build

Everything comes from the Nix flake.

    nix develop -c cmake -B build -G Ninja
    nix develop -c cmake --build build
    nix develop -c ctest --test-dir build --output-on-failure

## Deployment

The CI publishes the image `ghcr.io/0xsharkboy/nx-discord-rpc-relay:main`. `deploy/` holds a
Compose file and an example environment.

1. Copy `deploy/compose.yml` and `deploy/relay.env.example` to the server, the latter as
   `relay.env`, and fill in the secrets (`DISCORD_CLIENT_SECRET`, `TOKEN_ENC_KEY`, optionally
   `ADMIN_KEY`) and `PUBLIC_BASE_URL`. Keep `relay.env` readable by its owner only.
2. Create the data directory, owned by uid 1000 (the image's user), **before** the first
   `docker compose up`. Otherwise Docker creates it as root and the relay cannot write to it:

       mkdir -p data && sudo chown 1000:1000 data

   Alternatively, set `user:` in `compose.yml` to the uid that owns `./data`.
3. `docker compose up -d`. The relay listens on `127.0.0.1:8080` only.
4. Put a TLS reverse proxy in front of it for `PUBLIC_BASE_URL`. `relay.env.example` sets
   `TRUST_PROXY=true`, so the rate limits key on the first `X-Forwarded-For` hop. The proxy must
   **overwrite** that header with the peer address, never append to it, or a client could choose
   its own rate-limit key:
   - nginx: `proxy_set_header X-Forwarded-For $remote_addr;` (not `$proxy_add_x_forwarded_for`);
   - Caddy: `reverse_proxy 127.0.0.1:8080` already replaces the header sent by untrusted clients.

   Without a proxy, set `TRUST_PROXY=false`.

`./data` holds the database (`relay.db`), the published icons and the SDK's home directory. Back
it up together with `TOKEN_ENC_KEY`: the stored Discord tokens cannot be decrypted without it.
