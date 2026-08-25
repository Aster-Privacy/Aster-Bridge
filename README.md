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
