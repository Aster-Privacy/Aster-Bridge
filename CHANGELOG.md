# Changelog

All notable changes to Aster Bridge are recorded here. Earlier history lives in the git log.

## 0.4.0 - 2026-06-15

### Added
- Internal Aster-to-Aster mail that is end-to-end encrypted now decrypts locally inside the Bridge, so your connected mail client can read it. Decryption happens entirely on your device; the server never sees your messages.

### Changed
- Redesigned the Configuration and Settings screens into clean, grouped cards that match the web app.
- Copying a value now shows a brief confirmation toast, and hover feedback across the app is instant.

## 0.3.1 - 2026-06-15

### Fixed
- Messages keep stable identifiers after you delete mail, so connected clients no longer mismatch or re-download messages.
- POP3 list and message sizes are now exact, and a rare crash on unusually formatted messages is gone.
- Sending now fails fast with a clear error when a server rejects your credentials, instead of silently retrying.
- Archiving, trashing, and marking spam fully clean up the old folder state behind the scenes.
- Live updates recover on their own after a busy burst of mail instead of going quiet, and only the update types a client asks for are sent.

### Changed
- Greatly expanded the automated test suite for steadier releases.

## 0.3.0 - 2026-06-14

### Added
- Aster Bridge now follows your operating system's light and dark color scheme automatically.
- Honors your system text size and reduced-motion preferences.

### Changed
- Redesigned the mail-client setup guides to be cleaner and easier to follow, with subtle row animations.
- Sharper app, taskbar, and window icons across every size.
- Brand-blue sync progress bar and a larger connected-status indicator.
- Modal shadow now matches the web app, and horizontal scrolling is gone.

### Fixed
- Much faster POP3 on large mailboxes, with accurate list and message sizes and correct deletion.
- Steadier connections: responses flush promptly, password hashing runs off the main thread, and API connections are hardened.
- More reliable IMAP CHECK handling.

## 0.2.6

- Baseline for this changelog. See the git history for earlier releases.
