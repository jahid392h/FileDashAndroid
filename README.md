# FileDash for Android

Same FileDash as the web version — `web/index.php` and `web/assets-setup.php` are the original files.
The APK bundles a static PHP and runs it on the phone (127.0.0.1 only); a WebView shows the exact same UI.

## Get the APK (GitHub, no PC tools needed)
1. Create a GitHub repo, upload this whole folder (keep `.github/` — it is a hidden folder).
2. Open **Actions → Build FileDash APK → Run workflow** (it also runs on every push).
3. When it is green, open the run → **Artifacts → FileDash-apk** → download, unzip, install the APK.
   (Allow "install unknown apps" for your browser/file manager.)

## First launch
1. Allow **All files access** (FileDash manages your phone storage; "Skip" = only the app's own folder).
2. The asset question appears (offline download or keep online) — same as the web version; downloads go to the app's private `assets` folder.
3. Create your account (stored on the phone in the app's private `.filedash`).

## What differs from the web version (only where a phone is different)
- File manager root = phone storage (`/storage/emulated/0`) instead of the web folder.
- Downloads/exports are saved to the phone's **Download** folder.
- Domain lookups go through Android (the bundled PHP has no DNS config).
- Only this app can talk to the local server (secret cookie).

## Updating the web files
Replace `web/index.php` (and/or `web/assets-setup.php`), then run `python3 tools/patch_index.py` (CI does it automatically).

## Notes
- arm64 phones only (all modern Android phones). Android 8+.
- Built with a debug signing key so it installs directly; use your own keystore for Play Store.
- Logs on the phone: `files/php_server.log`, `files/php_errors.log` (app private folder).
