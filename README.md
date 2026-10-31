# My Gallery — Personal Offline Gallery & Private Vault
Plain HTML/CSS/JS. No servers, analytics or dependencies. All data stays in your browser (IndexedDB).

## Deploy on GitHub Pages
1. Download/unzip all files, keeping them together in one folder.
2. On github.com create a new repository (e.g. `my-gallery`), click **Add file → Upload files**, drag in every file (index.html, style.css, script.js, manifest.json, service-worker.js, README.md, the three icon PNGs), then **Commit**.
3. Repository **Settings → Pages → Build from branch → main / (root) → Save**.
4. After a minute open `https://YOUR-NAME.github.io/my-gallery/` in Chrome on Android.
5. Chrome menu (⋮) → **Add to Home screen / Install app**.

## Test offline
Open the app once online, close it, turn on airplane mode, open it from the home screen. Saved media, notes and vault unlock still work.

## Test moving items
1. Add a photo (+ → Add Photos). Long-press it (or tap ⋮) → **Move to Private Album**; set a password when asked.
2. It disappears from Normal Gallery and appears in Private Vault (☰ → Private Vault).
3. Long-press it there → **Move to Normal Gallery**.

## Verify originals are never deleted
The app only stores a copy of what you pick. Open your phone's Gallery/Files app before and after deleting or moving in My Gallery: the originals are still there.

## Honest limits
- Clearing site data or uninstalling the browser deletes everything. Forgetting the vault password makes private items unrecoverable.
- Vault: AES-GCM 256, PBKDF2-SHA256 (310,000 iterations), random salt and per-item IV; the password/key is never stored. Locks after 2 minutes idle or when the app is hidden. Unlocked content is held in memory, so it is only as safe as your device.
- Chrome may not fire hidden/lock events in every situation. Very large videos are decrypted in memory and can fail on low-RAM phones.
- Offline works only after the first successful online load. Web Share with files depends on Android/Chrome support; otherwise the file is downloaded.
- Not included: backup/restore. Use Download (single or multi-select) for backups.
- Biometric unlock needs a platform authenticator AND the WebAuthn PRF extension (recent Android Chrome with a screen lock set). If unsupported, only the passcode is offered. Your device decides whether it uses fingerprint, face or screen lock.
- Changing the passcode re-encrypts every private item in one all-or-nothing step and resets biometric unlock.
- Only a syntax check was run on the code; it was not tested on a device.
