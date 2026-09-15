<img width="200" alt="Aster Bridge" src="bridge_logo.png" />

# Aster Bridge

Aster Bridge is a free, open-source local mail relay for Aster Mail. It lets any standard desktop email client connect to your Aster account over IMAP, SMTP, and JMAP, and lets any contacts app sync your address book over CardDAV.

Your mail and contacts stay end-to-end encrypted on Aster's servers. The bridge decrypts them locally on your machine so your client can read them, and re-encrypts what you send before it leaves your device. We have no way to read your mail and we never will.

You can sign up at [astermail.org](https://astermail.org). Aster Bridge requires a Star plan or higher.

## How it works

The bridge runs silently in the background and exposes local IMAP, SMTP, JMAP, POP3, and CardDAV servers on 127.0.0.1. Your mail client and contacts app connect to these local ports using an app password you generate inside the bridge. All encryption and decryption happens locally, and no plaintext travels over the network.

| Protocol | Default port |
|---|---|
| IMAP (STARTTLS) | 1143 |
| IMAP (implicit TLS) | 1993 |
| SMTP (STARTTLS) | 1025 |
| JMAP | 1080 |
| CardDAV | 1081 |
| POP3 | 1110 |
| POP3 (implicit TLS) | 1995 |

Ports shift automatically if something else is using them. The bridge UI always shows the actual ports in use.

## Getting started

1. Download the latest installer from [Releases](https://github.com/Aster-Privacy/Aster-Bridge/releases)
2. Open Aster Bridge. On first launch it shows a pairing code
3. Enter the code at [app.astermail.org/link-device](https://app.astermail.org/link-device) to link your account
4. Go to the **App Passwords** tab and generate a password for your mail client
5. Add an IMAP/SMTP account in your client pointing at `127.0.0.1` with the ports and app password shown in the bridge
6. To sync contacts, add a CardDAV account in your contacts app using the account URL shown on the **CardDAV Server** card, with the same username and app password

CardDAV works with any client that speaks RFC 6352, including Contacts on macOS and iOS, DAVx5 on Android, and Thunderbird. Your contacts are decrypted on your device only, and the bridge serves them over the loopback interface, so they never travel over the network.

TLS is on by default using a self-signed certificate generated on your machine. Your mail client or contacts app warns the first time you connect; accept the certificate to continue. The bridge shows the certificate path and SHA-256 fingerprint on the TLS screen so you can verify it.

## Install on Linux

Each release carries a `.deb`, an `.rpm`, a pacman package for Arch Linux, and an AppImage. Install the package that matches your distribution, or make the AppImage executable with `chmod +x` and run it.

On Arch Linux, download `Aster-Bridge-x86_64.pkg.tar.zst` from the release and install it with pacman:

```
sudo pacman -U Aster-Bridge-x86_64.pkg.tar.zst
```

The package installs `aster-bridge` in `/usr/bin` and adds Aster Bridge to your app launcher. To build the same package yourself, run `makepkg` in `packaging/arch`.

Aster Bridge draws its window with WebKitGTK, which every package expects to find on the system. If the app starts but the window stays empty, install the WebKitGTK 4.1 runtime for your distribution:

| Distribution | Package |
|---|---|
| Debian, Ubuntu | `libwebkit2gtk-4.1-0` |
| Arch Linux | `webkit2gtk-4.1` |
| Fedora | `webkit2gtk4.1` |
| openSUSE | `libwebkit2gtk-4_1-0` |

## Run Aster Bridge from the command line

The `aster-bridge` command-line tool runs the same IMAP, SMTP, POP3, JMAP, and CardDAV servers as the desktop app, without a window. Use it on servers, headless machines, and terminals over SSH. It needs the same Star plan or higher, and it checks your plan the same way the desktop app does.

### Install the command-line tool

Each release carries an archive for your platform, with a matching `.sha256` checksum file:

| Platform | Archive |
|---|---|
| Linux (x86-64) | `aster-bridge-cli-x86_64-unknown-linux-gnu.tar.gz` |
| Linux (ARM64) | `aster-bridge-cli-aarch64-unknown-linux-gnu.tar.gz` |
| macOS (Apple silicon and Intel) | `aster-bridge-cli-universal-apple-darwin.tar.gz` |
| Windows (x64) | `aster-bridge-cli-x86_64-pc-windows-msvc.zip` |

To install on Linux, download the archive and its checksum, verify it, and put the binary on your `PATH`:

```
sha256sum -c aster-bridge-cli-x86_64-unknown-linux-gnu.tar.gz.sha256
tar -xzf aster-bridge-cli-x86_64-unknown-linux-gnu.tar.gz
install -m 755 aster-bridge-cli-x86_64-unknown-linux-gnu/aster-bridge ~/.local/bin/
```

The Linux binary doesn't need WebKitGTK, GTK, or D-Bus libraries. On macOS, use `shasum -a 256 -c` to verify the archive. If you download it with `curl` instead of a browser, macOS doesn't ask you to confirm the first launch. On Windows, extract the zip file and run `aster-bridge.exe` from PowerShell or Command Prompt.

### Sign in

To link the tool to your account, run:

```
aster-bridge login
```

The tool shows a code. Enter it at [app.astermail.org/link-device](https://app.astermail.org/link-device) in a browser where you're signed in to Aster Mail, and the tool finishes signing in. If you can't keep the terminal open, run `aster-bridge login --no-wait`, enter the code, and then run `aster-bridge login` again within 10 minutes.

### Start the servers

To run the servers in the foreground, run `aster-bridge serve`. Press Control-C to stop them. In another terminal, `aster-bridge status` shows your account, plan, ports, and sync state.

If your plan no longer includes Aster Bridge, `serve` stops with exit code 4 and tells you how to upgrade. The tool also stops when you sign this device out from another app or when the session expires.

To create a password for your email app, run `aster-bridge app-password create --label "Laptop"`. The password appears once, so copy it before you close the terminal. Use `aster-bridge app-password list` and `aster-bridge app-password revoke ID` to manage passwords, and `aster-bridge tls fingerprint` to verify the certificate that your email app shows.

The command-line tool keeps its own account, cache, and settings, so it can run alongside the desktop app. If both run on the same computer, give the command-line tool different ports:

```
aster-bridge config set imap_port 2143
aster-bridge config set smtp_port 2025
```

### Run in the background

To start Aster Bridge automatically, sign in and then run `aster-bridge service install`. The tool registers itself with your platform's service manager:

| Platform | Service manager |
|---|---|
| Linux | A systemd user service |
| macOS | A launchd agent |
| Windows | A startup entry that runs when you sign in |

Use `aster-bridge service status` to check the service and `aster-bridge service uninstall` to remove it. On Linux, a user service stops when you sign out. To keep it running without an active session, run `sudo loginctl enable-linger $USER`.

### Store keys without a system keychain

The tool stores its keys in the system keychain: the macOS Keychain, Windows Credential Manager, or the Secret Service on Linux. Servers often don't run a Secret Service. To store keys in an encrypted file instead, create a key and point the tool at it:

```
openssl rand -hex 32 > ~/.config/aster-bridge.key
chmod 600 ~/.config/aster-bridge.key
export ASTER_BRIDGE_SECRET_KEY_FILE=~/.config/aster-bridge.key
aster-bridge --secret-backend file login
```

Set `ASTER_BRIDGE_SECRET_BACKEND=file` so every command uses the file. Under systemd, you can supply the key as a credential named `secret-key` instead. Keep the key somewhere safe, because the tool can't read your account without it.

### Colors

Aster Bridge colors its output when your terminal supports color, and it matches those colors to your terminal background. To choose the background yourself, use `--theme`:

```
aster-bridge --theme dark status
aster-bridge --theme light status
```

To turn color off, or to keep it on when you redirect output to a file, use `--color`:

```
aster-bridge --color never status
aster-bridge --color always status > status.txt
```

To set either one for every command, use the `ASTER_BRIDGE_THEME` and `ASTER_BRIDGE_COLOR` environment variables. Aster Bridge also honors `NO_COLOR`, and it never colors `--json` output.

### Data folders and scripting

The tool keeps its data in the following folder. To use another folder, pass `--data-dir` or set `ASTER_BRIDGE_DATA_DIR`.

| Platform | Folder |
|---|---|
| Linux | `~/.local/share/com.astermail.bridge.cli` |
| macOS | `~/Library/Application Support/com.astermail.bridge.cli` |
| Windows | `%LOCALAPPDATA%\com.astermail.bridge.cli` |

Add `--json` to any command for machine-readable output. Every command exits with one of these codes:

| Code | Meaning |
|---|---|
| 0 | The command succeeded. |
| 1 | An error occurred. |
| 2 | The command or its options aren't valid. |
| 3 | You aren't signed in, or the servers aren't running. |
| 4 | Your plan doesn't include Aster Bridge, or the plan check failed. |
| 5 | The session expired or this device was signed out. |
| 6 | The keychain or key file isn't available. |
| 7 | Another Aster Bridge process is using the data folder. |

## Build from source

Building the desktop app takes two steps, because the Rust binary embeds the web interface at compile time. Build the interface first, then the binary:

```
git clone https://github.com/Aster-Privacy/Aster-Bridge.git
cd Aster-Bridge
npm install
npm run tauri:build
```

`npm run tauri:build` runs both steps and writes installers to `src-tauri/target/release/bundle/`. To produce only the binary, run `npm run build` first, then `cargo build --release` in `src-tauri/`. A bare `cargo build` or `cargo install` without a preceding `npm run build` stops with an error telling you which step is missing, so you never get a binary with nothing to display.

To work on the app, run `npm run tauri:dev`. This build loads the interface from the Vite dev server on `http://localhost:5174` instead of from the binary, and it is the only build that expects a dev server to be running.

Building on Linux also needs the WebKitGTK, GTK, and app indicator development packages. On Debian and Ubuntu:

```
sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev \
  libayatana-appindicator3-dev librsvg2-dev libxdo-dev build-essential
```

On Arch Linux:

```
sudo pacman -S webkit2gtk-4.1 gtk3 libayatana-appindicator librsvg xdotool base-devel
```

## Documentation

Full setup guides, including per-client instructions, app passwords, ports and TLS, and troubleshooting, are at [astermail.org/bridge/docs](https://astermail.org/bridge/docs).

## Community

Join our [Discord](https://discord.gg/R4XqRUfgWZ) to share feedback, ask questions, and contribute to the privacy community. You can also find us on [X](https://x.com/AsterPrivacy) and [Reddit](https://www.reddit.com/r/AsterPrivacy).

If you have any questions or security disclosures, email us at [hello@astermail.org](mailto:hello@astermail.org) or [security@astermail.org](mailto:security@astermail.org). **Do not open a public issue for security vulnerabilities.** Read [SECURITY.md](SECURITY.md) for the full security vulnerability disclosure process.

## Contributing

We welcome contributions of all kinds. Read [CONTRIBUTING.md](https://github.com/Aster-Privacy/.github/blob/main/CONTRIBUTING.md) before opening a pull request.

By contributing to any Aster repository, you agree that your contributions will be licensed under [AGPL v3](https://www.gnu.org/licenses/agpl-3.0.en.html).
