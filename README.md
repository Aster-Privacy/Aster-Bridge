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

## Documentation

Full setup guides, including per-client instructions, app passwords, ports and TLS, and troubleshooting, are at [astermail.org/bridge/docs](https://astermail.org/bridge/docs).

## Community

Join our [Discord](https://discord.gg/R4XqRUfgWZ) to share feedback, ask questions, and contribute to the privacy community. You can also find us on [X](https://x.com/AsterPrivacy) and [Reddit](https://www.reddit.com/r/AsterPrivacy).

If you have any questions or security disclosures, email us at [hello@astermail.org](mailto:hello@astermail.org) or [security@astermail.org](mailto:security@astermail.org). **Do not open a public issue for security vulnerabilities.** Read [SECURITY.md](SECURITY.md) for the full security vulnerability disclosure process.

## Contributing

We welcome contributions of all kinds. Read [CONTRIBUTING.md](https://github.com/Aster-Privacy/.github/blob/main/CONTRIBUTING.md) before opening a pull request.

By contributing to any Aster repository, you agree that your contributions will be licensed under [AGPL v3](https://www.gnu.org/licenses/agpl-3.0.en.html).
