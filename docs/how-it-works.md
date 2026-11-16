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
  - `key_hash`: the SHA-256 of your API key. The key itself is never stored, so the relay cannot
    show it again;
  - `access_sealed` and `refresh_sealed`: your Discord access and refresh tokens, encrypted (see
    below);
  - `access_expires_at`: when the access token expires;
  - `link_broken`: set when Discord no longer accepts the tokens.
  - `last_seen_at`: when the console last sent a presence update, kept to within an hour (see
    [Inactive accounts](#inactive-accounts)).
- `votes`: icon votes, one row per (title id, image hash, Discord user id) with its creation time.
  See [Icons](#icons).
- `published_icons`: the title id, image hash and publication time of each published icon. It does
  not record who voted for it.
- `blocked_hashes`: hashes of images an admin removed.

Published icons are also written as JPEG files under `icons/` in the data directory.

The Discord Social SDK keeps its own files under the process's `HOME` directory, which the Docker
image places at `/data/home`. Their content is managed by the SDK.

## What is not kept

- **Play history.** Presence reports (title name, details, elapsed time, title id) are held in
  memory only, to send them to Discord, and their content is never written to the database. Two things are kept: the time of your last
  update, to within an hour, in `last_seen_at` (see [Inactive accounts](#inactive-accounts)); and
  icon votes: a vote records that your account uploaded an icon for a given title, and it is kept
  for about 30 days (see [Icons](#icons)).
- **IP addresses.** IPs are used only as keys for the in-memory rate limits on `POST /v1/link` and
  `POST /v1/link/{link_id}/poll` (IPv6 addresses are cut to their /64 prefix). Entries are
  swept once they have been idle for an hour, but a sweep only runs on a request to the same route
  at most once an hour, so an idle entry can stay in memory for about two hours. All of them are
  lost on restart.
  The relay never writes a client IP to the database or to its logs.
- **Pending links.** A link in progress lives in memory only. Once linked, the relay keeps the new
  API key in memory for 60 seconds so that a console can fetch it again after a dropped response.

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

The account is also marked `link_broken` when Discord refuses the access token while the relay
connects you for presence: either Discord answers `401 Unauthorized` when the Social SDK hands it
the token, or it closes the connection with "authentication failed".

A broken link keeps its row, including the encrypted tokens, until you unlink, link again, or the
account has been inactive for 90 days (see [Inactive accounts](#inactive-accounts)). The
console then gets `409 link_broken` on presence updates and should offer to link again.

## Unlinking

`DELETE /v1/me` (the Unlink action on the console):

- deletes your `users` row and all of your icon votes at once, so the API key stops working;
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
`users` row and all of the account's icon votes are deleted, and both Discord tokens are revoked a
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

Consoles upload the icon of the title being played. An icon must be a 256x256 JPEG of at most
131072 bytes; the relay re-encodes it before serving it.

Each upload is a vote from one Discord account for one image of one title. An icon is published
once `PUBLISH_THRESHOLD` distinct accounts (2 by default) have uploaded the same image for the same
title. A published icon is not replaced by votes. Votes are deleted 30 days after they were cast
(the cleanup runs once a day). Unlinking deletes all of your votes at once, including votes for
icons already published; published icons themselves stay.

Published icons are served at `/icons/{title_id}.jpg`, which is the URL Discord loads. An admin
(holder of `ADMIN_KEY`) can publish or replace an icon directly, and can remove one, which also
blocks that exact image.

## Rate limits

| Route | Limit | Key |
|---|---|---|
| `POST /v1/link` | 10 per hour | client IP |
| `POST /v1/link/{link_id}/poll` | 720 per hour | client IP |
| `PUT /v1/icons/{title_id}` | 30 per hour | API key (the admin key is exempt) |

See [protocol.md](protocol.md#rate-limits) for the details.

## Logs

The relay writes to standard output and standard error only.

- **Request lines:** one per request, with the method, the path, the status code and the duration,
  for example `PUT /v1/presence 204 3ms`. The link id in `/v1/link/{link_id}/poll` is replaced by
  `:id`. Paths of icon routes include the title id. No IP address, header, API key, token or
  request body is logged.
- **Errors:** failures are logged with a short description. Some of them name the Discord user id
  concerned (a failed refresh, a dropped Discord connection, a presence update Discord refused,
  errors reported by the Social SDK).
- **Maintenance:** the daily cleanup logs how many inactive accounts it deleted, without naming them.

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
