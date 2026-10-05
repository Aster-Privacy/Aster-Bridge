# Changelog

All notable changes to Aster Bridge are recorded here. Earlier history lives in the git log.

## 1.0.3 - 2026-10-05

### Fixed
- After your encryption keys change, Aster Bridge opens the messages and custom domain addresses that are protected with your earlier keys.

## 1.0.2 - 2026-10-05

### What's new
- Labels that you add in Aster Mail appear as keywords on your messages in your mail app.

### Fixed
- When you sign out, Aster Bridge closes every open connection from your mail apps and confirms that it removed your local data.
- Encrypted messages that Aster Bridge couldn't open before now sync to your mail app, and a message whose sender can't be verified is marked as unverified.
- A search with deeply nested conditions returns an error instead of slowing down Aster Bridge.
- On Linux, Aster Bridge keeps its window sandbox turned on whenever your system supports it.

## 1.0.1 - 2026-10-04

### What's new
- Folders open faster and searches return sooner in your mail app, especially in large mailboxes.
- Attachments for older messages download several at a time, so a new mailbox finishes syncing sooner.
- Contacts and calendar apps connect faster after the first sign-in with an app password.

### Fixed
- Attachments with accented or non-Latin file names keep their names when you download them.
- Sender and recipient names that contain commas or other punctuation display correctly.
- If two Aster Bridge services are set to the same port, Aster Bridge repairs the setting and starts normally.
- Aster Bridge renews its local certificate before the certificate expires, and it reports an error if the certificate can't be loaded.
- Your mail app no longer downloads a folder again after a temporary read error.

## 1.0.0 - 2026-10-03

### What's new
- Aster Bridge reaches version 1.0 and is no longer in beta.

### Fixed
- Aster Bridge stays signed in after your computer wakes from sleep, and it no longer sends a message twice when a send is retried.
- Messages that you send go only to the recipients that your mail app specifies, and a send that fails permanently stops retrying.
- If Aster Bridge can't save a message with all of its attachments, your mail app shows an error instead of saving the message without them.
- Opening a folder in read-only mode no longer marks its messages as read.
- Messages that you delete on another device now disappear from large folders too, and attachment downloads no longer stall the rest of the sync.
- Aster Bridge answers requests from mail and contacts apps more accurately, so folders, searches, and message counts match what is on the server.
- Connections to Aster stay protected if the certificate authority for Aster's servers changes.

## 0.4.38 - 2026-10-02

### Fixed
- Every message that your mail app saves to the Sent folder now appears there. Previously, a sent message could go missing when another recent message had the same subject, which happened most often with templated or repeated mail.
- When you copy a message to another folder, the original now stays where it was, and the copy keeps its flags, tags, and date.
- Moving or searching for the last message in a folder now acts on that message only, instead of on every message in the folder.
- Searches that your mail app runs over a range of messages, such as all unread messages, now return results.
- If you hide the Aster Bridge icon in the system tray, it now stays hidden after Aster Bridge restarts.

## 0.4.37 - 2026-09-30

### What's new
- Tags and keywords that you add to a message in your mail app now stay on the message, and you can search for messages by tag.
- Searches that your mail app runs on the server now return results when the app specifies a character set or when you search for accented or non-Latin words.

### Fixed
- When your mail app changes labels on a message, the message keeps its read and starred status instead of becoming unread.
- Aster Bridge checks search requests more strictly and no longer writes the text that you search for to its log.

## 0.4.36 - 2026-09-28

### What's new
- Aster Bridge has a refreshed design with filled panels and fields, clearer banners and progress bars, and a new button for installing updates.
- When another app is already using a port that Aster Bridge needs, Bridge tells you which port is taken and suggests free ports that you can use instead.

### Fixed
- Aster Bridge refreshes your session in the background instead of signing in again every 50 minutes, and it waits before it retries a refresh that fails.
- You can send messages up to 70 MB, and when the server refuses an attachment, your mail app shows the reason instead of a general error.
- On Windows, Aster Bridge runs the tool that protects its data folder from the Windows system folder only, so a program with the same name in another folder cannot run in its place.
- Copy buttons keep their icon after you copy, buttons keep their size while they load, labels and elapsed times are translated, and layouts display correctly in right-to-left languages.

## 0.4.35 - 2026-09-28

### What's new
- Your custom folders and subfolders appear in your mail app over IMAP and JMAP, nested under their parent folders.
- You can create, rename, move, and delete folders from your mail app, and each change also appears in the Aster apps.
- You can copy and move messages into and out of your custom folders.

### Fixed
- Messages show their Cc and Reply-To addresses in your mail app, so Reply All includes everyone who was copied.
- Messages that you import from an MBOX file, or add from your mail app, keep their Cc and Reply-To addresses.
- When your mail app saves a message to Sent, Aster Bridge no longer mistakes it for an earlier message with the same subject and drops it.

## 0.4.34 - 2026-09-20

### Fixed
- Aster Bridge now signs in with your default sending address instead of always using your primary Aster address.
- You can send from a custom domain address in the mail app you connect to Bridge.
- Bridge refreshes your list of sending addresses when your mail app offers one it does not recognize, so an address you add after signing in works without signing in again.
- Bridge records which sending addresses it skipped at sign-in, which makes a missing address easier to diagnose.

## 0.4.33 - 2026-09-15

### What's new
- Aster Bridge now has a command-line tool. Run the same IMAP, SMTP, POP3, JMAP, and CardDAV servers on a server, a headless machine, or over SSH, with no window and no desktop libraries. Sign in with `aster-bridge login`, start the servers with `aster-bridge serve`, and run `aster-bridge service install` to start them at login. It keeps its own account, cache, and settings, so it runs alongside the desktop app. The README explains how to install it, store keys without a system keychain, and read its exit codes.
- The command-line tool colors its output to match your terminal background. Use `--theme` and `--color` to choose, and it honors `NO_COLOR`.

### Fixed
- Your contacts now reach your mail app over CardDAV. Earlier versions asked the server for the wrong address and returned no cards at all.
- App passwords now show their creation time in your own time zone, so it no longer looks later than the time they were last used.
- Aster Bridge writes far fewer log messages while it syncs. Replies that keep their conversation and contacts it can't read no longer each write a warning.

## 0.4.32 - 2026-09-14

### Fixed
- Aster Bridge now starts when its local database contains tables it didn't create, for example after another tool wrote to the same folder. It repairs the database, or moves it aside and starts with a fresh one, instead of quitting before the window opens.

## 0.4.31 - 2026-09-14

### Fixed
- When you reply to a message from your mail app through Aster Bridge, the reply now stays in the same conversation for you and for the recipient. Earlier versions sent every reply as a new conversation, including replies between Aster addresses.
- Messages that you send through Aster Bridge now appear in your Sent folder on the web, in the Aster apps, and in your mail app.
- Aster Bridge now refreshes your session in the background, so it no longer signs in again every 50 minutes.

## 0.4.30 - 2026-09-03

### Fixed
- Messages that you send from your mail app through Aster Bridge now include their attachments. Earlier versions delivered the message without the files, and no error told you.
- Inline images in HTML messages that you send arrive in place.
- Messages that wait in the outbox and go out later keep their attachments.
- Drafts that you saved on the web with attachments now show those attachments in your mail app, and sending a draft through JMAP includes the attachments, the Cc and Bcc recipients, and the HTML formatting.

## 0.4.29 - 2026-09-03

### Fixed
- Aster Bridge now downloads the attachments of your messages, so they open in your mail app the same way they do on the web. Messages that arrived earlier with the "Aster Bridge cannot download yet" note get their attachments during the next few syncs, and your mail app fetches the completed message on its own.
- Inline images in HTML messages show in place.
- If the attachments of a message are still downloading, or Aster Bridge could not decrypt them, a short note at the end of the message says so.
- Attachment names that contain quotes, non-Latin characters, or line breaks are encoded safely in the message headers.

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
