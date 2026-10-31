# Auto Key Solver

Fully-automatic Delta (Roblox executor) key renewal for Android. Pure Java + native Android APIs, zero third-party dependencies, APK is only ~30 KB.

> License: [MIT](LICENSE)

## Features

- **Auto HWID extraction**: reads `Internals/.license` first (decodes the engine's delta-XOR chain head when the file carries one — authoritative, no phase assumption; otherwise restores the true HWID from the rotated mirror unit, cross-checking against `Crashes/` when available), falls back to the newest files in `/sdcard/Delta/Crashes/`
- **Auto solving**: `identifier = SHA-256(HWID)` -> `POST /public/start {service:6}` -> automatic checkpoint chain (AES-CTR fingerprint, r= callback decoding, about:blank polling) -> `whitelist/6` verification
- **Auto write-back**: the fresh key is written to `Internals/Cache/license` and `Internals/Settings/delta_key` (bare key, single line) so Delta opens already verified, no manual entry
- **Key expiry display**: queries the session (`/public/start` is idempotent -> `session/status`) for the server's real `minutesLeft` and shows the exact expiry time and remaining validity; live validity check with green/red status
- **Auto renewal on key expiry**: the next alarm fires 10 minutes before the key's real expiry (server `minutesLeft` ground truth, 24h fallback), and a 30-minute watchdog re-checks validity server-side and starts a solve only when the key has really expired — so a missed alarm (Doze, OEM battery managers) can no longer leave you with a dead key
- **HWID saved & cross-checked**: the verified HWID is kept in the app's private storage (Delta deletes `.license` when the key expires — the saved copy keeps solving possible), and every fresh read is arbitrated against the saved one via the live key before it may overwrite it
- **Configurable daily automation**: pick your own renewal time (tap the daily switch row); the main alarm uses `setAlarmClock` (exact, Doze-safe, no exact-alarm permission needed) and the app asks for the battery-optimization exemption so OEM battery managers don't kill it; the renewal worker is started with a plain `startService` (no Android 12+ background-FGS crash) with an inline goAsync+wakelock fallback; re-armed after every firing, on boot and on every app open

## Build

No Gradle needed — just JDK 21+ and Android build-tools 34 + android.jar. From the repo root, with `$SDK` pointing at your Android SDK (any shell, commands shown POSIX-style; on Windows use `aapt2.exe` / `d8.bat`):

```bash
BT=$SDK/build-tools/34.0.0                          # aapt2, d8, zipalign, apksigner
AJ=$SDK/platforms/android-35/android.jar
mkdir -p out/gen out/classes

# resources + manifest -> base.apk (also generates R.java)
"$BT/aapt2" compile --dir app/res -o out/res.zip
"$BT/aapt2" link -o out/base.apk -I "$AJ" --manifest app/AndroidManifest.xml \
    --min-sdk-version 26 --target-sdk-version 34 --java out/gen --auto-add-overlay out/res.zip

# java -> dex
javac --release 11 -encoding UTF-8 -cp "$AJ" -d out/classes $(find app/src out/gen -name '*.java')
jar cf out/classes.jar -C out/classes .
"$BT/d8" --release --lib "$AJ" --output out out/classes.jar

# pack classes.dex into the apk, align, sign (any keystore works)
(cd out && zip -u base.apk classes.dex)
"$BT/zipalign" -f 4 out/base.apk out/aligned.apk
"$BT/apksigner" sign --ks ~/.android/debug.keystore --ks-pass pass:android \
    --ks-key-alias androiddebugkey --out AutoKeySolver.apk out/aligned.apk
```

No keystore yet? Create one: `keytool -genkeypair -keystore debug.keystore -alias androiddebugkey -storepass android -keypass android -dname CN=debug -validity 10000`.

## Tests

```bash
python test_license_formats.py
```

Runs a Python port of `DeltaStore`'s HWID extraction against synthetic `.license` samples (current delta-XOR-head format, legacy tiling, headless mirror, garbage) — no real device data, no dependencies.

## Getting the build tools

- build-tools 34: `https://dl.google.com/android/repository/build-tools_r34-windows.zip` (extracts to a folder named `android-14`; includes aapt2, d8, zipalign, apksigner)
- platform android.jar: `https://dl.google.com/android/repository/platform-35_r02.zip` (take `android-35/android.jar`)
- JDK 21: any distribution

## Layout

```
├── app/
│   ├── AndroidManifest.xml
│   ├── res/values/strings.xml
│   └── src/com/auto/keysolver/
│       ├── MainActivity.java   # UI + permission flow
│       ├── KeyRunner.java      # shared solve flow
│       ├── Solver.java         # Platoboost protocol (start/step/whitelist)
│       ├── DeltaStore.java     # HWID extraction + key cache read/write
│       ├── Scheduler.java      # daily alarm
│       ├── AutoService.java    # scheduled foreground service
│       ├── AutoReceiver.java   # alarm receiver
│       └── BootReceiver.java   # re-arm alarm after boot
└── LICENSE             # MIT
```

## How it works (short version)

Delta stores its local key cache in plain files under `/sdcard/Delta/`. On startup the executor reads the key from these files and re-validates it against the server (`GET /public/whitelist/6?identifier=<sha256-hwid>&key=<key>`); when the server answers `valid=true`, the app unlocks without showing the key screen. This tool automates obtaining a fresh key bound to the device HWID and writing it into those cache files.

## Disclaimer

This project only automates renewal of a license the user is entitled to, on their own device. Use at your own risk.
