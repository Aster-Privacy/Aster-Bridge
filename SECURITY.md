<img width="200" alt="Aster" src="https://raw.githubusercontent.com/Aster-Privacy/.github/main/profile/aster_logo.png" />

# Aster Security Policy

## Reporting a vulnerability

**Don't open a public GitHub issue for a security vulnerability.**

Send your report to security@astermail.org, or submit it through our vulnerability disclosure program on Bugcrowd: https://bugcrowd.com/engagements/aster-privacy-vdpc

We acknowledge reports within 48 hours, prioritize fixes by severity, and keep you updated until the issue is resolved.

## Scope

This policy covers all Aster products and infrastructure:

- Aster Mail (astermail.org)
- All repositories under github.com/Aster-Privacy

## Safe harbor

We don't pursue legal action against researchers who:

- Report vulnerabilities in good faith
- Don't access, modify, or exfiltrate user data
- Don't disrupt service availability or degrade the user experience
- Give us a reasonable amount of time to respond before public disclosure

## Encryption architecture

Aster Bridge decrypts your mail locally on your device using keys derived from your Aster vault. Mail that you send to another Aster user is encrypted on your device before it leaves. Mail to an outside address is handed to the Aster mail server over TLS for delivery, unless the bridge can encrypt it with the recipient's OpenPGP key. The local IMAP, POP, SMTP, JMAP, and CardDAV servers only accept connections from clients on 127.0.0.1.

| Channel | Protocol |
|---|---|
| Aster Bridge to Aster backend | TLS 1.2+ (HTTPS), bearer token auth with Ed25519 device keys |
| Bridge to mail client (local) | Plaintext or self-signed TLS on loopback only |
| Aster to Aster | X3DH and Double Ratchet with ML-KEM-768 (post-quantum) |
| Aster to external recipients | Ed25519 OpenPGP when the recipient publishes a key, with portable keys that work with any OpenPGP client |

App passwords are stored as salted Argon2id hashes in the bridge's encrypted local database. The key for that database is kept in the OS credential store (Windows Credential Manager, macOS Keychain, Linux Secret Service), or in a key file if you choose the file backend. Access tokens are zeroed from memory on drop.

## Coordinated disclosure

We follow coordinated disclosure. Give us adequate time to patch a vulnerability before you publish it. If you would like public credit, say so in your report.

## Acknowledgments

We thank the researchers who help keep Aster secure.

- [diogovbs](https://github.com/diogovbs) (October 2026): a series of private reports covering the Bridge's IMAP, POP3, and SMTP handling and its desktop updater. We fixed every finding in coordination with the reporter.
