# Privacy policy

Last updated: 2026-11-17

This policy covers the official NX Discord RPC relay at `https://nx-discord-rpc.0xsharkboy.dev`,
used by the Discord application "NX RPC" and by the
[NX Discord RPC](https://github.com/0xsharkboy/nx-discord-rpc) Switch homebrew by default. The
technical details behind each statement are in [How the relay works](docs/how-it-works.md).

## Who runs it

The official instance is operated by 0xsharkboy on a server in the European Union. For requests
about your data, write to <nx-rpc@0xsharkboy.dev>. For anything else, open an issue at
<https://github.com/0xsharkboy/nx-discord-rpc-relay/issues>.

## What the relay does

When you link your Discord account, you authorize the "NX RPC" application through Discord's
OAuth2 device flow. The relay requests the scopes `openid sdk.social_layer_presence` and nothing
else. Your console then reports the title you are playing to the relay, and the relay shows it as
your Discord Rich Presence through the official Discord Social SDK. The console never handles a
Discord token.

## What is collected and why

Stored in the relay's database:

- **Discord user id and username**, to identify your linked account.
- **Your Discord avatar id**, the short code Discord uses to name your profile picture (not the
  picture itself), so your console can show your profile picture. The relay reads it, with your
  username, when you link and again each time it refreshes your tokens, about once a week.
  Accounts linked before this version get it read once, shortly after the relay is updated.
- **Discord access and refresh tokens**, encrypted, to set your presence and keep the link working.
- **A hash (SHA-256) of your console's API key**, to recognize your console. The key itself is not
  stored.
- **Link status and token expiry time**, to refresh the tokens and tell your console when the link
  is broken.
- **The time of your last presence update**, to within an hour, to delete inactive accounts.
- **Icon files**: when your console uploads a title's icon, the relay stores the image, keyed by a
  hash (SHA-256) of its bytes, with the dates it was created and last used. A stored icon records no
  user and no title. Anyone who knows a hash can load the image, and a moderation block on a hash
  applies to everyone.
- **Icons published before this version**: the title id, image hash and publication time of icons
  that were published by title, and the icon image itself. They do not record who uploaded them.

Held in memory only, never written to the database:

- **Your current presence**, as sent by the console: the title name, the details text, the elapsed
  time, the title id and the hash of the icon it shows. It is used only to send it to Discord.
  This is also the only place that links you to an icon, and it lasts only as long as your session.
- **IP addresses**, used only as keys for the rate limits on the linking routes.
- **Links in progress**, and a newly issued API key for 60 seconds after linking.

The Discord Social SDK also keeps its own files on the server, managed by the SDK.

## Legal basis

- Linking, storing your account data and setting your presence rely on your **consent**, given when
  you authorize "NX RPC" in Discord. You can withdraw it at any time (see [Your rights](#your-rights)).
- Rate limits and the handling of abuse rely on our **legitimate interest** in keeping the service
  available and safe.

## How long data is kept

- **Account data** (id, username, avatar id, tokens, key hash, last activity) is kept until you
  unlink. It is deleted automatically after **90 days** without an accepted presence update.
- **Icon files** are deleted after **30 days** without use. A file counts as used when a presence
  shows it or when it is uploaded, and a file that a live presence shows is kept. They do not
  identify you.
- **Your presence** is cleared from Discord after **150 seconds** without a report from your
  console, and is lost from memory when the relay restarts.
- **Rate limit entries** are dropped after about two hours of inactivity at most, and on restart.
- **Logs**: the relay logs one line per request (method, path, status, duration) without IP
  addresses, headers, keys, tokens or request bodies. Some error messages name the Discord user id
  concerned. The logs are rotated at three files of 10 MB each.

## What is not collected

- Your Discord password or Discord account token.
- Your messages, servers, friends or any other Discord data: the requested scopes do not give
  access to them.
- Your play history. Presence reports are not written to the database; only the time of your last
  update is kept, as described above.
- IP address logs. The relay never writes a client IP to its database or its logs. The reverse
  proxy in front of it keeps no access log for this site; its error log, kept in the host's system
  journal, can record an IP address when a request fails at the proxy.

## Sharing

Your data is sent only to Discord, to set your presence and to manage your tokens. It is not sold,
not used for analytics or advertising, and not shared with any other third party.

Your console downloads your profile picture itself from Discord's public image server
(`cdn.discordapp.com`), without any token; Discord then sees your console's IP address. The relay
does not download, store or forward the picture.

## Security

Discord tokens are encrypted with AES-256-GCM before they are stored. The encryption key is held by
the operator and is never stored in the database. The relay's files are readable by its own user
only, and consoles reach the relay over HTTPS.

## Your rights

Under the GDPR you have the right to access, correct and delete your data, to restrict or object to
its processing, to data portability, and to withdraw your consent.

- **Delete your data:** use **Unlink** in the homebrew. It deletes your account row at once, clears your presence and then revokes your Discord tokens.
- **Revoke access in Discord:** remove "NX RPC" under User Settings > Authorized Apps. This stops
  the relay from acting for you, but only breaks the link: the stored data stays until you unlink,
  link again, or the account is deleted after 90 days of inactivity.
- **See what is stored:** the relay's `GET /v1/me` route returns your username, link status and
  current presence to your console. For a copy of everything stored about you, write to
  <nx-rpc@0xsharkboy.dev> and give your Discord username.
- **Anything else about your data:** write to <nx-rpc@0xsharkboy.dev>. Never send tokens or API
  keys, by email or in a public issue.

You also have the right to lodge a complaint with a data protection supervisory authority, such as
the CNIL in France or the authority of the country where you live.

## Children

The service requires a Discord account, so Discord's own minimum age requirements apply.

## Self-hosted instances

The relay is open source and anyone can run their own instance. This policy covers only the
official instance. A self-hosted relay is the responsibility of whoever runs it.

## Changes

Changes to this policy are dated above and recorded in the history of this repository.
