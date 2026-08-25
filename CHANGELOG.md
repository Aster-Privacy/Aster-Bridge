# Changelog

All notable changes to Aster Bridge are recorded here. Earlier history lives in the git log.

## 0.4.28 - 2026-08-25

### Added
- On Mac, Aster Bridge now has a full menu bar: **About Aster Bridge**, **Check for Updates**, **Settings** (Command-Comma), an **Edit** menu, a **View** menu with **Sync Now** (Command-R), a **Window** menu, and a **Help** menu.
- The menu bar icon now shows the bridge status, and lets you start or stop the bridge, sync now, open settings, and check for updates without opening the window.
- The app remembers the size and position of its window between launches.
- You get a system notification when an update is available and when a message can't be sent.

### Changed
- On Mac, the menu bar icon is now a monochrome template image, so it matches the other status items in light and dark menu bars.
- On Mac, closing the window removes Aster Bridge from the Dock and the app switcher while it keeps running in the menu bar. Click the menu bar icon to bring it back.
- On Mac, background mode no longer leaves a Dock icon with no window behind it.
- Quitting waits up to a few seconds for queued messages to finish sending before the app closes.
- The About panel and Finder now show the copyright and app category.

## 0.4.27 - 2026-08-25

### Changed
- The app icon on Mac now sits on a white rounded tile, so it matches the other apps in the Dock.

## 0.4.26 - 2026-08-24

### Fixed
- The AppImage now opens on Arch Linux, Fedora, and other distributions that ship a recent version of Mesa. It stopped at a blank window and an `EGL_BAD_PARAMETER` error before, because it carried its own copy of a system graphics library that the graphics driver could no longer use.
- The AppImage now starts on systems that do not have the ALSA sound library installed, instead of stopping with a missing library error.
- Building Aster Bridge from source with `cargo build` or `cargo install` now produces an app that shows its own interface. It previously tried to load the interface from a development server and showed "Could not connect to localhost: Connection refused".
- Building the app before you build the web interface now stops with a message telling you which step to run, instead of finishing and leaving you with an app that has nothing to display.

## 0.4.20 - 2026-08-19

### Fixed
- Copying mail into your Aster account no longer times out in mail clients that limit how long they wait for a reply. Bridge now confirms that it's still working while it stores each message, so large migrations finish instead of retrying the same message forever.

## 0.4.17 - 2026-08-11

### Fixed
- Copying mail from another provider into your Aster account now works. Any mailbox accepts copied messages, not only Sent and Drafts, and each message keeps its original date, sender, and read state.
- Copied mail now appears in the web app and on your phone, not only in the mail client that copied it.
- Copying the same mail twice no longer creates duplicates, so an interrupted migration is safe to run again.
- Large migrations no longer stall partway through. Bridge waits out the account rate limit instead of dropping messages, and moving or copying more than 100 messages at once now succeeds.
- Searching by header, cc, bcc, or keyword now returns only matching messages. Mail clients that search before copying no longer skip your mail.
- Creating a mailbox that already exists now succeeds, so clients that set up a folder tree before copying no longer stop with an error.
- A message larger than the 40 MB limit now fails on its own instead of disrupting the rest of the session.

### Security
- Bridge no longer shares its local IMAP, POP, and SMTP ports on Windows, so another app on your computer can't take them over.

## 0.4.15 - 2026-08-01

### Fixed
- Message dates now render correctly in connected mail clients (a 0.4.14 regression could show malformed Date headers).
- Opening a message in a mail client now marks it read in your Aster account, not just locally.
- Queued sends interrupted by a crash or shutdown are picked up again on restart instead of being silently dropped.
- Send retries no longer deliver duplicates when the first attempt actually went through.
- Existing caches migrate their stored message dates so search and sorting work on mail synced by older versions.
- Read and flag changes made elsewhere now appear immediately in clients that keep an open connection.

### Security
- Updated bundled dependencies (quinn-proto).

## 0.4.14 - 2026-08-01

### Fixed
- Apple Mail no longer errors with "APPEND not supported" when saving sent messages, and send retries no longer deliver duplicates; saves to Sent are matched against the copy already stored in your account.
- Deleting messages over IMAP, POP3, or JMAP now deletes them in your Aster account as well, so deleted mail no longer comes back.
- Messages deleted, moved, read, or starred in the web and mobile apps now sync down to connected mail clients.
- Marking mail read or unread in Apple Mail now reliably syncs to your account.
- Moving, flagging, and deleting messages from JMAP clients now works and syncs everywhere.
- Read-only mailbox sessions can no longer modify or expunge messages, and UID EXPUNGE only removes the messages it names.
- Quoted-phrase searches and date-based searches now return correct results, and message dates display correctly in every client.
- Mailbox updates while a client is idling now report the exact removed message, keeping message lists consistent.

## 0.4.1 - 2026-06-16

### Changed
- Refreshed the Configuration and Settings screens: a clearer connection status with a colored status icon, a larger Connect/Disconnect button, and tidier cards.
- Toast notifications now match the web app, copying a value shows a toast instead of changing color, and hover feedback is instant with a pointer cursor on controls.
- Setup guide popups no longer flicker when closing.

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
