# Auto Key Solver

Fully-automatic Delta (Roblox executor) key renewal for Android. Pure Java + native Android APIs, zero third-party dependencies, APK is only ~30 KB.

> License: [MIT](LICENSE)

## Features

- **Auto HWID extraction**: reads the newest files in `/sdcard/Delta/Crashes/` (most frequent 64-hex string), falls back to `Internals/.license`
- **Auto solving**: `identifier = SHA-256(HWID)` -> `POST /public/start {service:6}` -> automatic checkpoint chain (AES-CTR fingerprint, r= callback decoding, about:blank polling) -> `whitelist/6` verification
- **Auto write-back**: the fresh key is written to `Internals/Cache/license` and `Internals/Settings/delta_key` (bare key, single line) so Delta opens already verified, no manual entry
- **Daily automation**: a 08:00 daily alarm starts a foreground service that renews silently and posts the result as a notification; re-armed automatically after reboot

## Build

No Gradle needed — just JDK 21 + Android build-tools 34 + android.jar:

```powershell
powershell -ExecutionPolicy Bypass -File build.ps1
```

Tool paths are at the top of `build.ps1` (`$sdk` / `$jdk` / `$signer`); adjust them for your machine.

Output: `out/base.apk` (aapt2 -> javac -> d8 -> zipalign -> v2+v3 signing).

## Getting the build tools

- build-tools 34: `https://dl.google.com/android/repository/build-tools_r34-windows.zip` (extracts to a folder named `android-14`)
- platform android.jar: `https://dl.google.com/android/repository/platform-35_r02.zip` (take `android-35/android.jar`)
- uber-apk-signer: `https://github.com/patrickfav/uber-apk-signer/releases` (v1.3.0)
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
├── build.ps1           # one-shot build script
└── LICENSE             # MIT
```

## How it works (short version)

Delta stores its local key cache in plain files under `/sdcard/Delta/`. On startup the executor reads the key from these files and re-validates it against the server (`GET /public/whitelist/6?identifier=<sha256-hwid>&key=<key>`); when the server answers `valid=true`, the app unlocks without showing the key screen. This tool automates obtaining a fresh key bound to the device HWID and writing it into those cache files.

## Disclaimer

This project only automates renewal of a license the user is entitled to, on their own device. Use at your own risk.
