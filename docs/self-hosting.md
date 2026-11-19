# Self-hosting the relay

This guide runs your own relay and points your consoles at it. You need:

- a Linux x86-64 server with Docker and Docker Compose;
- a domain name served over HTTPS by a reverse proxy. Consoles only accept an `https://` relay
  URL, and Discord loads the title icons from `PUBLIC_BASE_URL/icons/...` and the badge from
  `PUBLIC_BASE_URL/badge.png`, so the relay must be reachable from the internet;
- a Discord account to create the Discord application.

## 1. Create the Discord application

1. In the [Discord Developer Portal](https://discord.com/developers/applications), create an
   application. Its **Application ID** is your `DISCORD_CLIENT_ID`.
2. Under **Discord Social SDK > Getting Started**, fill in the form and submit it to enable the
   Social SDK for the application.
3. Under **OAuth2**, reset and copy the **Client Secret**: this is your `DISCORD_CLIENT_SECRET`.
   Keep it private.
4. Under **Rich Presence > Art Assets**, upload an image with the key `switch_logo`. The relay
   shows it when a title has no icon.

What the relay needs from the application, and nothing more:

- **OAuth2 device flow with the client secret.** The relay links accounts with the OAuth2 device
  authorization flow and authenticates every call to Discord (device authorization, token
  exchange, refresh, revoke) with the client ID and secret. It does not use the Social SDK's own
  sign-in, so **Public Client** does not need to be enabled.
- **Scopes:** `openid sdk.social_layer_presence`, requested by the relay itself.
- **No redirect URI:** the device flow does not use one, and the relay sends none.

## 2. Get the Discord Social SDK

The relay is built against the Discord Social SDK, which is proprietary and not part of this
repository.

1. Once the Social SDK is enabled for your application, open **Discord Social SDK > Downloads** in
   the Developer Portal, accept the terms, and download the C++ SDK for Linux.
2. Unpack it so that these two files exist in your clone of this repository:

       third_party/discord_social_sdk/include/discordpp.h
       third_party/discord_social_sdk/lib/release/libdiscord_partner_sdk.so

   `third_party/discord_social_sdk/` is ignored by git.

The SDK must not be redistributed: do not commit it, and do not push an image built with it to a
public registry. Keep your image local or in a private registry.

Without the SDK, CMake stops with `Discord Social SDK not found in <dir>: see docs/self-hosting.md`.

## 3. Build the image

Build the image on the server that will run it, from the root of the repository, with the SDK in
place:

    docker build -t nx-discord-rpc-relay:local .

The build compiles the relay, runs the test suite, and produces an Ubuntu 24.04 image that runs as
the user `ubuntu` (uid 1000). The Dockerfile copies the SDK from
`third_party/discord_social_sdk` only: a `COPY` error on that path means step 2 was skipped or the
SDK is somewhere else.

The image contains the SDK. To build it on another machine, move it to the server directly
(`docker save nx-discord-rpc-relay:local | ssh <server> docker load`) or through a private
registry, never a public one.

### Building without Docker

Everything comes from the Nix flake:

    nix develop -c cmake -B build -G Ninja
    nix develop -c cmake --build build
    nix develop -c ctest --test-dir build --output-on-failure

To use an SDK stored elsewhere, pass its directory to CMake:

    nix develop -c cmake -B build -G Ninja -DDISCORD_SDK_DIR=/path/to/discord_social_sdk

## 4. Configure

Copy `deploy/compose.yml` and `deploy/relay.env.example` to the server, the latter as `relay.env`,
and fill it in, in the directory holding `compose.yml`. Keep `relay.env` readable by its owner only (`chmod 600 relay.env`).

| Variable | Required | Meaning |
|---|---|---|
| `DISCORD_CLIENT_ID` | yes | The application ID (a decimal number) |
| `DISCORD_CLIENT_SECRET` | yes | The application's client secret |
| `TOKEN_ENC_KEY` | yes | Base64 of exactly 32 random bytes: `openssl rand -base64 32`. Encrypts the stored Discord tokens |
| `PUBLIC_BASE_URL` | yes | The relay's public URL, `https://`, no trailing slash, at most 200 characters. Icons and the badge are served from it |
| `ADMIN_KEY` | no | Admin key for icon moderation (`DELETE /v1/icons/{hash or title_id}`) and for icon uploads without a rate limit, see [protocol.md](protocol.md) |
| `TRUST_PROXY` | no | `true` to key the rate limits on the first `X-Forwarded-For` hop, default `false` (the example sets `true`) |
| `LISTEN_ADDR` | no | `host:port` to listen on inside the container, default `0.0.0.0:8080` |
| `DATA_DIR` | no | Data directory inside the container, default `/data` |
| `BADGE_URL` | no | Link opened by a click on the NX Discord RPC badge (a small image consoles can ask for, see `badge` in [protocol.md](protocol.md)). An https URL of at most 256 characters. Default: `https://github.com/0xsharkboy/nx-discord-rpc` |
| `MIN_CLIENT_VERSION` | no | Oldest console version served, `X.Y.Z`. Older consoles get `426 client_outdated` on every `/v1/` route except `DELETE /v1/me` (unlink) and stop showing their presence; from v0.6.0 they also show that an update is required, older ones are not told why. Unset or empty: no minimum (the default). See [Client versions](#9-client-versions) |

`PUBLISH_THRESHOLD` from earlier versions is no longer used: if it is still set, the relay ignores it
and logs a line saying so.

The relay refuses to start, and says which variable is wrong, when a required variable is missing or
a value is invalid.

In `compose.yml`, set `image:` to the tag you built, for example `nx-discord-rpc-relay:local`.

## 5. Run

1. In the directory holding `compose.yml`, create the data directory, owned by uid 1000 (the
   image's user), **before** the first `docker compose up`. Otherwise Docker creates it as root and
   the relay cannot write to it:

       mkdir -p data && sudo chown 1000:1000 data

   Alternatively, set `user:` in `compose.yml` to the uid that owns `./data`.
2. `docker compose up -d`. The relay listens on `127.0.0.1:8080` only.
3. Check it: `curl http://127.0.0.1:8080/healthz` answers `ok`.

## 6. Reverse proxy

Put a TLS reverse proxy in front of the relay for `PUBLIC_BASE_URL`. `relay.env.example` sets
`TRUST_PROXY=true`, so the rate limits key on the first `X-Forwarded-For` hop. The proxy must
**overwrite** that header with the peer address, never append to it, or a client could choose its
own rate-limit key:

- nginx: `proxy_set_header X-Forwarded-For $remote_addr;` (not `$proxy_add_x_forwarded_for`);
- Caddy: `reverse_proxy 127.0.0.1:8080` already replaces the header sent by untrusted clients.

Set TRUST_PROXY=false only when clients reach the relay directly (local testing); consoles require https, so production needs a TLS proxy.

## 7. Backups

`./data` holds the database (`relay.db`, in SQLite WAL mode, so with its `-wal` and `-shm` files),
the stored icons (`icons/`) and the SDK's home directory (`home/`). Back up the whole directory,
ideally with the relay stopped, **together with `TOKEN_ENC_KEY`**: the stored Discord tokens cannot
be decrypted without it. Losing the key means every user has to link again.

### Before upgrading

Stop the relay and back up `./data` (at least `relay.db` with its `-wal` and `-shm` files) before
running a new image. A new relay migrates the database schema forward on start, and an older
image refuses to start on a database written by a newer one, so the backup is the only way back.

## 8. Point your consoles at it

For each console, take the SD card out, and on a PC set `relay_url` in
`config/nx-discord-rpc/config.ini` (`sdmc:/config/nx-discord-rpc/config.ini` on the console):

    relay_url = https://relay.example.com

Edit the file with the SD card in a PC, not while the console is running: the sysmodule rewrites
`config.ini` from its settings in memory whenever a setting changes, which would undo the edit. It
reads the file at boot. Put the card back, start the console, then link the account again from the
app: an API key only works with the relay that issued it.

See [how-it-works.md](how-it-works.md) for what the relay stores and logs.

## 9. Client versions

Once a day, starting a day after it starts, the relay logs how many distinct accounts used each
console version over the last 24 hours, for example:

    relay: client versions in the last 24 h: 0.6.0=120 0.5.0=14 other=2

`other` counts accounts whose requests came from a client that is not the official console, or
whose User-Agent carries no `X.Y.Z` version. Only requests with a valid API key are counted, and
the counts are held in memory only: a restart starts a new window.

Leave `MIN_CLIENT_VERSION` unset unless a breaking change requires it. Before raising it, follow
the [compatibility policy](protocol.md#compatibility-policy) and check these lines: every console
below the new minimum stops showing its presence until it is updated. Consoles from v0.6.0 show
that an update is required. Consoles v0.5.0 and older are not told why: their Status tab still
says Linked and relay OK, Test connection reports "The relay refused the last update (error 426)",
and linking again says "Something went wrong". Raise the minimum only once these lines show few
consoles older than v0.6.0. Every console can still unlink (`DELETE /v1/me` is never refused).

A console that is refused is no longer counted, since it is turned away before its key is checked,
except when it unlinks. On start, the relay logs the minimum it enforces.

### Relay and console versions

The relay and the console homebrew have separate version numbers: a relay release does not need a
console release, and the reverse. Which consoles a relay serves depends on the API and on
`MIN_CLIENT_VERSION`, not on matching numbers. Each relay release is tagged `vX.Y.Z` in this
repository, and the relay logs its version on start (`relay 0.1.2 listening on ...`).

| Relay | Consoles served | Notes |
|-------|-----------------|-------|
| 0.1.2 | v0.1.0 and newer | Presence text that is not valid UTF-8 (some game and homebrew names) is repaired instead of refused. Refusals are logged with their reason. |
| 0.1.1 | v0.1.0 and newer | Every feature up to console v0.7.0, including the badge. Same data layout as 0.1.0. |
