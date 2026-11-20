# How the relay works

For the official instance, see also the [privacy policy](../PRIVACY.md) and [terms of service](../TERMS.md).

This page describes what the relay does with your data. It is written from the code in this
repository: the official instance at `https://nx-discord-rpc.0xsharkboy.dev` is operated by
0xsharkboy and runs this relay. Anything that happens outside the relay process (the reverse proxy
in front of it, the host's log retention, backups) is up to whoever operates an instance and is not
covered by the code.

## Overview

The Switch never sees a Discord token. Linking uses the OAuth2 device flow: the console asks the
relay to start a link, you approve it on another device at discord.com, and the relay receives the
Discord tokens and gives the console an API key of its own. From then on the console sends its
current title to the relay with that key, and the relay shows it as your Discord Rich Presence
through the official Discord Social SDK.

The relay requests the OAuth2 scopes `openid sdk.social_layer_presence` and nothing else.

## What is stored

The relay keeps one SQLite database, `relay.db` in the data directory, with these tables:

- `users`, one row per linked Discord account:
  - `discord_id`: your Discord user id;
  - `username`: your Discord username;
  - `avatar`: the id Discord gives your profile picture (not the picture itself), empty when you have
    none;
  - `key_hash`: the SHA-256 of your API key. The key itself is never stored, so the relay cannot
    show it again;
  - `access_sealed` and `refresh_sealed`: your Discord access and refresh tokens, encrypted (see
    below);
  - `access_expires_at`: when the access token expires;
  - `link_broken`: set when Discord no longer accepts the tokens.
  - `last_seen_at`: when the console last sent a presence update, kept to within an hour (see
    [Inactive accounts](#inactive-accounts)).
- `icon_files`: one row per stored icon image, with its SHA-256 hash, the time it was created and the
  time it was last used. It has no user and no title. See [Icons](#icons).
- `published_icons`: the title id, image hash and publication time of icons published by title
  before v0.4.0, served read-only. It does not record who uploaded them.
- `blocked_hashes`: hashes of images an admin removed.

Icons are also written as JPEG files under `icons/` in the data directory, named after their hash.

Before it upgrades the database schema, a new relay copies `relay.db` next to it as
`relay.db.schema-v<N>.bak`, so a failed upgrade can be undone. A copy holds the same data as the
database at that time, including accounts deleted since, and is deleted at the first daily cleanup
once it is 14 days old.

The Discord Social SDK keeps its own files under the process's `HOME` directory, which the Docker
image places at `/data/home`. Their content is managed by the SDK.

## What is not kept

- **Play history.** Presence reports (title name, details, elapsed time, title id, icon hash) are held in
  memory only, to send them to Discord, and their content is never written to the database. One thing is kept: the time of your last
  update, to within an hour, in `last_seen_at` (see [Inactive accounts](#inactive-accounts)).
- **Which icon you show.** The link between your account and an icon hash is held in memory during
  your session only (see [Icons](#icons)).
- **IP addresses.** IPs are used only as keys for the in-memory rate limits on `POST /v1/link` and
  `POST /v1/link/{link_id}/poll` (IPv6 addresses are cut to their /64 prefix). Entries are
  swept once they have been idle for an hour, but a sweep only runs on a request to the same route
  at most once an hour, so an idle entry can stay in memory for about two hours. All of them are
  lost on restart.
  The relay never writes a client IP to the database or to its logs.
- **Pending links.** A link in progress lives in memory only. Once linked, the relay keeps the new
  API key in memory for 60 seconds so that a console can fetch it again after a dropped response.
- **Which console version you use.** To count how many accounts still use each console version,
  the relay keeps, in memory only, the hashes of the API keys seen with each version (read from
  the console's `User-Agent`) over the current 24 hours. Once a day it logs the totals per version
  and clears the sets; a restart clears them too. No version is written to the database or logged
  for an account. Requests without a key (linking) are not counted.

## Token encryption

Discord tokens are encrypted with AES-256-GCM before they are stored. Each token gets a fresh
random 12-byte nonce, and the stored value is the nonce, the ciphertext and the 16-byte
authentication tag. The 32-byte key comes from the `TOKEN_ENC_KEY` environment variable (base64)
and is never stored in the database. Without that key the stored tokens cannot be decrypted.

The relay creates its files with owner-only permissions (umask `077`).

## Token refresh

Every 10 minutes the relay refreshes the tokens of linked accounts whose access token expires within
the next 24 hours. When Discord rejects a refresh token, or when a stored token cannot be decrypted,
the account is marked `link_broken`; when Discord is unreachable or answers with an unexpected error,
the relay tries again on the next run. When Discord says the relay's own client credentials are
invalid, the run stops without touching any account.

After each successful refresh, the relay reads your Discord identity again with the new access token
and updates your stored `username` and `avatar`, so a renamed account or a new profile picture shows up
within about a week. This step is best effort: if Discord does not answer, or answers for a different
account, the stored values are kept and the refresh itself is unaffected.

Accounts linked before avatars existed have no stored avatar id yet. On its next run (shortly after
the update), the relay reads the identity once for each of them, using the stored access token, and
keeps trying on each later run until Discord answers. Until then `GET /v1/me` leaves `discord_id`
and `avatar` out, so the console shows no avatar rather than a wrong one.

The link poll result and `GET /v1/me` return two fields for the console: `discord_id`, and `avatar`
(the avatar id, or null when you have none). The relay only hands out the id. The console builds the
image address and downloads the picture from `cdn.discordapp.com` itself.

The account is also marked `link_broken` when Discord refuses the access token while the relay
connects you for presence: either Discord answers `401 Unauthorized` when the Social SDK hands it
the token, or it closes the connection with "authentication failed".

A broken link keeps its row, including the encrypted tokens, until you unlink, link again, or the
account has been inactive for 90 days (see [Inactive accounts](#inactive-accounts)). The
console then gets `409 link_broken` on presence updates and should offer to link again.

## Unlinking

`DELETE /v1/me` (the Unlink action on the console):

- deletes your `users` row at once, so the API key stops working;
- clears your presence and disconnects you from Discord;
- revokes your Discord access and refresh tokens a few seconds later, in the background.

The revocation is best effort: the relay does not check Discord's answer and does not retry, and a
revocation not yet sent when the relay shuts down is dropped (the log then says how many). It is
also skipped if the account links again before it is sent, since it would cut off the new link. A
revocation already on its way to Discord cannot be called back, so a link made within a few seconds
of an unlink may be cut off and need to be redone. You can always remove the application's access
yourself in Discord, under User Settings > Authorized Apps.

Linking the same Discord account again (for example from another console) replaces the stored
tokens and the API key: the previous key stops working at once. The relay does not revoke the
replaced tokens: Discord revokes every token it issued to the application for an account as soon as
any one of them is revoked, so doing so would also cut off the new link. The replaced tokens are
revoked along with the current ones when you unlink, when the account is deleted for inactivity, or
when you remove the application in Discord. The relay overwrites the replaced tokens and
keeps no copy of them.

## Inactive accounts

An account with no accepted presence update (`PUT /v1/presence`) for **90 days** is deleted,
whether its link works or is broken. Linking counts as activity; updates refused with an error (such
as `409 link_broken` or `400 invalid_body`) do not. The deletion is the same as an unlink: the
`users` row is deleted, and both Discord tokens are revoked a
few seconds later, best effort. The console then gets `401 unauthorized` and has to link again.

To limit writes, `last_seen_at` is updated at most once an hour per account, and the check runs
once a day, so an account is deleted between 90 days (less up to an hour) and 91 days after its
last update. Accounts that existed before this rule count as seen at the upgrade.

## Presence

- The relay sends at most one change to Discord every 5 seconds per account.
- It clears your presence after **150 seconds** without a report from the console, so a console that
  loses Wi-Fi or goes to sleep drops off Discord on its own. The Discord connection for that account
  is closed 60 seconds after the clear.
- When the relay shuts down it clears every presence it shows before disconnecting.

## Icons

Consoles send the SHA-256 hash of the icon of the title being played with each presence update. The
relay answers whether it already stores that image. When it does not, the console uploads it. An
icon must be a 256x256 JPEG of at most 131072 bytes; the relay re-encodes it before serving it.

Icon files are named after the hash of the uploaded bytes and are shared: the same image uploaded
by two users is one file. The relay stores no user and no title with a file, only its hash, the
time it was created and the time it was last used. Which icon your presence shows is held in memory
during your session only, and is lost when the relay restarts or you stop sending presence. The upgrade
to this version deleted the per-user records of earlier versions and rewrote the database file so
no user id from them stays on disk.

A file is used when a presence shows it and when it is uploaded. Once a day the relay deletes the
files unused for 30 days, except those a live presence shows. The relay keeps at most 10000 files
and refuses new images (`503 storage_full`) past that. So that one account cannot fill it, an
account can store at most 50 new images a day, counted in memory only by its API key's hash.

Icons are served at `/icons/{hash}.jpg`, which is the URL Discord loads. Anyone who knows a hash can
load its image, and a stored image can be shown by any user who sends its hash. An admin (holder of
`ADMIN_KEY`) can remove an icon, which blocks that hash for everyone: presences that sent it show
the Switch logo instead. Icons published by title before v0.4.0 are still served at
`/icons/{title_id}.jpg`, read-only, unless their image is blocked, and are used when a presence has
no usable icon.

## Rate limits

| Route | Limit | Key |
|---|---|---|
| `POST /v1/link` | 10 per hour | client IP |
| `POST /v1/link/{link_id}/poll` | 720 per hour | client IP |
| `PUT /v1/icons/{title_id}` | 30 per hour | API key (the admin key is exempt) |
| `PUT /v1/icons/{title_id}`, new images only | 50 per day | API key (the admin key is exempt) |

See [protocol.md](protocol.md#rate-limits) for the details.

## Logs

The relay writes to standard output and standard error only.

- **Request lines:** one per request, with the method, the path, the status code and the duration,
  for example `PUT /v1/presence 204 3ms`. The link id in `/v1/link/{link_id}/poll` is replaced by
  `:id`. Paths of icon routes include the title id. No IP address, header, API key, token or
  request body is logged. A refused request (other than `404`) ends with its error code and the
  relay's own message, for example `PUT /v1/presence 400 2ms invalid_body: name must be a string of 1
  to 128 bytes`; neither contains request data.
- **Errors:** failures are logged with a short description. Some of them name the Discord user id
  concerned (a failed refresh, a dropped Discord connection, a presence update Discord refused,
  errors reported by the Social SDK).
- **Maintenance:** the daily cleanup logs how many inactive accounts it deleted, without naming them.
- **Client versions:** once a day, the number of distinct accounts per console version over the
  last 24 hours, for example `relay: client versions in the last 24 h: 0.6.0=120 0.5.0=14 other=2`.
  It names no account.
- **Refused requests:** once a day, the number of refused requests per error code over the last 24
  hours, for example `relay: refused requests in the last 24 h: client_outdated=12 invalid_body=3`.
  It names no account.

How long these logs are kept depends on the host. With the Compose file in `deploy/`, Docker keeps at
most three log files of 10 MB each and rotates older lines out.

## On the official instance

The official relay runs at `https://nx-discord-rpc.0xsharkboy.dev` and is operated by 0xsharkboy.

- **Reverse proxy:** a Caddy server terminates TLS in front of the relay. It has no access log for
  this site, so ordinary requests leave no IP on disk. Caddy's own error log, kept in the system
  journal of the proxy host, can record a client IP when a request fails at the proxy; it is kept
  according to that host's journal rotation.
- **Relay logs:** the container logs are rotated at three files of 10 MB each and contain no IP
  addresses (see [Logs](#logs)).
- **Backups:** there are no automatic backups of the relay data yet. If the data were lost,
  consoles would only need to link again.

## Who operates it

The official instance, `https://nx-discord-rpc.0xsharkboy.dev`, is operated by 0xsharkboy. You can
also run your own: see [self-hosting.md](self-hosting.md).
