<img width="200" alt="aster_horizontalv2" src="https://github.com/user-attachments/assets/a337e975-996d-4672-a92b-b809591f389a" />

# Aster Security Policy

## Properly Reporting a Vulnerability

**Please ensure you do not open a public GitHub issue for security-related vulnerabilities.**

Send your report to this email: security@astermail.org

We will read your report within 48 hours and make sure to resolve critical vulnerabilities within seven days. We will make sure to keep you updated throughout the entire process.

## Scope

This security policy covers all of our Aster products and infrastructure:

- Aster Mail (astermail.org)
- All repositories under github.com/Aster-Privacy

## Safe Harbor

We will never pursue legal action against researchers who:

- Report vulnerabilities in good faith
- Do not access, modify, or exfiltrate user data
- Do not disrupt service availability or degrade user experience
- Allow us a reasonable timeframe to respond before public disclosure

## Encryption Architecture

Aster Bridge decrypts your mail locally on your machine using keys derived from your Aster vault. No plaintext ever leaves your device through the bridge - the local IMAP/SMTP/JMAP servers only speak to clients on 127.0.0.1.

| Channel | Protocol |
|---|---|
| Aster Bridge - Aster Backend | TLS 1.2+ (HTTPS), bearer token auth with Ed25519 device keys |
| Bridge - Mail Client (local) | Plaintext or self-signed TLS on loopback only |
| Aster → Aster mail | X3DH + Double Ratchet with ML-KEM-768 (post-quantum) |
| Aster → External mail | RSA-4096 OpenPGP |

App passwords are stored in the OS credential store (Windows Credential Manager, macOS Keychain, Linux Secret Service). Access tokens are zeroed from memory on drop.

## Coordinated Disclosure

We follow coordinated disclosure. Please give us adequate time to patch the vulnerability before publishing. We are happy to credit you publicly if you would like - just let us know in your report.

## Acknowledgements

We thank the researchers who help keep Aster secure. Credited disclosures will be listed below once we receive them.
