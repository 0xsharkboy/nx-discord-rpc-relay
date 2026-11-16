# nx-discord-rpc relay

Relay server for [nx-discord-rpc](https://github.com/0xsharkboy/nx-discord-rpc), the Nintendo
Switch homebrew that shows what you are playing as your Discord Rich Presence.

The console never handles a Discord token. You link your Discord account once with the OAuth2
device flow (scan a QR code, approve on your phone), the relay gives the console an API key of its
own, and the console reports its current title to the relay over HTTPS. The relay sets the presence
on your behalf through the official Discord Social SDK.

The official instance, `https://nx-discord-rpc.0xsharkboy.dev`, is operated by 0xsharkboy and is
what the homebrew uses by default.

## Documentation

- [How it works](docs/how-it-works.md): what the relay stores and logs, token encryption, refresh
  and revocation, presence timing, icons and rate limits.
- [Self-hosting](docs/self-hosting.md): create a Discord application, get the Social SDK, build
  your own image, deploy it, and point your consoles at it.
- [Protocol](docs/protocol.md): the HTTP API between the console and the relay.

## Privacy and terms

The official instance is covered by its [privacy policy](PRIVACY.md) and
[terms of service](TERMS.md). A self-hosted instance is the responsibility of whoever runs it.

## Build

The relay is C++20 (cpp-httplib, SQLite, OpenSSL) and needs the Discord Social SDK, which is
proprietary and not included in this repository. Download it from the Discord Developer Portal and
place it in `third_party/discord_social_sdk` (or pass `-DDISCORD_SDK_DIR=<dir>` to CMake): see
[self-hosting](docs/self-hosting.md#2-get-the-discord-social-sdk).

Everything else comes from the Nix flake:

    nix develop -c cmake -B build -G Ninja
    nix develop -c cmake --build build
    nix develop -c ctest --test-dir build --output-on-failure

`deploy/` holds a Compose file and an example environment; the Docker image is built from the
`Dockerfile` at the root. The image contains the SDK, so keep it out of public registries.

Before upgrading a deployment, back up `relay.db`: the relay migrates its schema forward on start,
and an older image refuses a newer database (see
[self-hosting](docs/self-hosting.md#before-upgrading)).

## License

[GNU Affero General Public License v3.0 or later](LICENSE). If you run a modified relay as a
service, you must offer its source code to its users.

Additional permission under GNU AGPL version 3 section 7: If you modify this program, or any
covered work, by linking or combining it with the Discord Social SDK (or a modified version of that
library), containing parts covered by the terms of the Discord Social SDK license, the licensors of
this program grant you additional permission to convey the resulting work. Corresponding Source for
a non-source form of such a combination need not include the source code of the Discord Social SDK,
but shall include that of the covered work.

The same text is in [NOTICE](NOTICE). The SPDX headers stay `AGPL-3.0-or-later`, since no standard
SPDX identifier covers this exception.
