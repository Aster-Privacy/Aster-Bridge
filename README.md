<img width="200" alt="aster_horizontalv2" src="https://github.com/user-attachments/assets/a337e975-996d-4672-a92b-b809591f389a" />

# Aster Bridge

Aster Bridge is a free, open-source local mail relay for Aster Mail. It lets any standard desktop email client - Thunderbird, Apple Mail, Outlook, and others - connect to your Aster account over IMAP, SMTP, and JMAP.

Your mail stays end-to-end encrypted on Aster's servers. The bridge decrypts it locally on your machine so your client can read it, and re-encrypts what you send before it leaves your device. We have no way to read your mail and we never will.

You can sign up at [astermail.org](https://astermail.org). Aster Bridge requires a Star plan or higher.

## How it works

The bridge runs silently in the background and exposes local IMAP, SMTP, and JMAP servers on 127.0.0.1. Your mail client connects to these local ports using an app password you generate inside the bridge. All encryption and decryption happens locally - no plaintext ever travels over the network.

| Protocol | Default port |
|---|---|
| IMAP (STARTTLS) | 1143 |
| IMAP (implicit TLS) | 1993 |
| SMTP (STARTTLS) | 1025 |
| JMAP | 1080 |

Ports shift automatically if something else is using them. The bridge UI always shows the actual ports in use.

## Getting started

1. Download the latest installer from [Releases](https://github.com/Aster-Privacy/Aster-Bridge/releases)
2. Open Aster Bridge - on first launch it shows a pairing code
3. Enter the code at [app.astermail.org/link-device](https://app.astermail.org/link-device) to link your account
4. Go to the **App Passwords** tab and generate a password for your mail client
5. Add an IMAP/SMTP account in your client pointing at `127.0.0.1` with the ports and app password shown in the bridge

TLS is enabled by default using a self-signed certificate generated on your machine. Your client will warn the first time - accept it. The bridge shows the certificate path and SHA-256 fingerprint on the TLS screen so you can verify it.

## Documentation

Full setup guides - per-client instructions, app passwords, ports and TLS, and troubleshooting - are at [astermail.org/bridge/docs](https://astermail.org/bridge/docs).

## Community

Join our [Discord](https://discord.gg/R4XqRUfgWZ) to give honest feedback, ask any questions, and contribute to the privacy community. You can also find us on [Twitter/X](https://twitter.com/asterprivacy) and [Reddit](https://www.reddit.com/r/AsterPrivacy).

If you have any questions or security disclosures, email us at [hello@astermail.org](mailto:hello@astermail.org) or [security@astermail.org](mailto:security@astermail.org). **Do not open a public issue for security vulnerabilities.** Read [SECURITY.md](SECURITY.md) for the full security vulnerability disclosure process.

## Contributing

We welcome contributions of all kinds. Read [CONTRIBUTING.md](https://github.com/Aster-Privacy/.github/blob/main/CONTRIBUTING.md) before opening a pull request.

By contributing to any Aster repository, you agree that your contributions will be licensed under [AGPL v3](https://www.gnu.org/licenses/agpl-3.0.en.html).
