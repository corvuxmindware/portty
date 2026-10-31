# Android build and release runbook

This runbook builds the Portty phone app for Android and produces a signed
release (Play Store AAB or sideload APK). It is the Android twin of
`MAC_IOS_BUILD_RUNBOOK.md`.

Run every command from the repository root unless a step says otherwise.

The committed package ID `org.example.portty` is an example. Set an ID you
control consistently in the Tauri config, Gradle namespace/application ID, and
Kotlin package/source paths before signing. If you use Firebase, its Android
app registration and local `google-services.json` must match that ID.

## 1. What this workflow produces

- A **release AAB** for Play Store upload:
  `app/src-tauri/gen/android/app/build/outputs/bundle/universalRelease/app-universal-release.aab`
- A **release APK** for direct sideload:
  `app/src-tauri/gen/android/app/build/outputs/apk/universal/release/`
- Package id `org.example.portty`, min SDK 24, target SDK 36.

For a debug install, run `pnpm tauri android dev` from `app/` with an Android
device or emulator connected.

## 2. Prerequisites

- Android Studio (or command-line SDK) with SDK 36, NDK, and platform-tools.
- `ANDROID_HOME` and `NDK_HOME` set, `adb` on PATH.
- Rust stable + the Android targets, Node.js, pnpm.

```sh
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
cd app
pnpm install --frozen-lockfile
cd ..
```

Never commit keystores, `key.properties`, `google-services.json`, pairing
tickets, PINs, or peer data. All of these are already git-ignored.

## 3. Record and validate the source

Use a reviewed commit and a clean working tree.

```sh
git rev-parse --short HEAD
git status --short
cargo test -p portty-app --test android_release_config
```

## 4. Choose the version code

Android's build number is `bundle > android > versionCode` in
`app/src-tauri/tauri.conf.json`. Google Play refuses any upload whose
`versionCode` is not higher than the last one, and devices refuse to update
to a lower code.

Bump it in **two places, kept identical**:

1. `app/src-tauri/tauri.conf.json` → `"android": { "versionCode": ... }`
2. `app/src-tauri/tests/android_release_config.rs` → the pinned assertion

Convention: `1000 + <build>` so it always stays above the historic
auto-derived `1000` (e.g. iOS TestFlight build 1.27 ↔ Android `1027`, the
first Play release). The marketing version (`versionName`) stays derived from
`version` in `tauri.conf.json` (`0.1.3`, matching the computer program) -
bump that only for real releases, on both platforms at once
(`tests/ios_release_config.rs` pins the iOS copies).

The oldest supported Android is 10 (`minSdk = 29` in
`gen/android/app/build.gradle.kts`, mirrored as `minSdkVersion` in
`tauri.conf.json`). Older system WebViews let the keyboard cover the typing
area; `android_release_config.rs` keeps the two values in step.

## 5. One-time: create the upload keystore

Generate a keystore (keep it OUTSIDE the repo or rely on the `*.jks`
git-ignore, and back it up - losing it locks you out of updating the app):

```sh
keytool -genkey -v -keystore app/src-tauri/gen/android/portty-upload.jks \
  -keyalg RSA -keysize 2048 -validity 10000 -alias portty
```

Then create `app/src-tauri/gen/android/key.properties` (git-ignored):

```properties
storeFile=../portty-upload.jks
storePassword=<store password>
keyAlias=portty
keyPassword=<key password>
```

`storeFile` is resolved relative to `gen/android/app/`. The gradle wiring in
`gen/android/app/build.gradle.kts` picks this file up automatically; when it
is absent, release builds are produced unsigned (same behavior as before the
wiring existed).

## 6. Optional: enable push (FCM) before building

Push stays dormant until `google-services.json` exists - follow
`PUSH-SETUP.md` §4 (Firebase console → add Android app → download
`google-services.json` into `app/src-tauri/gen/android/app/`, never commit
it). With the file present, the first launch on Android 13+ asks for
notification permission automatically.

## 7. Build

```sh
cd app
pnpm tauri android build          # AAB (Play upload)
pnpm tauri android build --apk    # APK (sideload)
```

Confirm the signature on the produced artifact:

```sh
"$ANDROID_HOME/build-tools/36.0.0/apksigner" verify --print-certs \
  src-tauri/gen/android/app/build/outputs/apk/universal/release/*.apk
```

An unsigned artifact here means `key.properties` was missing or wrong - see
§5.

## 8. Install or upload

Sideload to a connected phone:

```sh
adb install -r src-tauri/gen/android/app/build/outputs/apk/universal/release/app-universal-release.apk
```

Play Store: Play Console → app `org.example.portty` → create a release
(internal testing first) → upload the AAB from §1 → roll out.

## 9. Final checklist

- [ ] `cargo test -p portty-app --test android_release_config` passes.
- [ ] `versionCode` bumped in both places (config + test).
- [ ] Artifact signature verified (§7).
- [ ] If push matters for this build: `google-services.json` was present at
      build time and the on-device checks in `PUSH-SETUP.md` §5 pass.
- [ ] No keystore, `key.properties`, or `google-services.json` staged in git.

## 10. Native library and NDK

The Rust code ships as `lib/arm64-v8a/libportty_app_lib.so`. Three settings
keep the release copy lean and anonymous; `android_release_config.rs` guards
them.

- **Stable NDK.** `gen/android/app/build.gradle.kts` pins
  `ndkVersion = "30.0.16248370"` (NDK r30, stable). Gradle uses it to strip
  the library; the Rust code is compiled and linked with the NDK in
  `NDK_HOME`. Install it side by side (Android Studio → SDK Manager → SDK
  Tools → NDK (Side by side), or `sdkmanager "ndk;30.0.16248370"`) and point
  `NDK_HOME` (and `ANDROID_NDK_ROOT`, if set) at
  `$ANDROID_HOME/ndk/30.0.16248370`. Never ship a beta NDK, and bump the pin
  and the variables together.
- **Stripped, with symbols for Play.** Release strips the library (about
  25 MB instead of 35 MB) and puts its symbol table into the AAB under
  `BUNDLE-METADATA/com.android.tools.build.debugsymbols/`, so Play Console can
  name functions in native crashes. For an APK upload, the same symbols are in
  `app/build/outputs/native-debug-symbols/<variant>/native-debug-symbols.zip`.
  Only debug builds keep symbols inside the library (`androidComponents` block).
- **No build-machine paths.** Panic messages embed source paths, which would
  reveal the builder's user name and folders. `pnpm tauri` runs
  `app/scripts/tauri.mjs`, which for `android build` (release) sets
  `CARGO_ENCODED_RUSTFLAGS` with `--remap-path-prefix` flags computed on the
  build machine (home → `~`, `CARGO_HOME` → `/cargo`, the checkout →
  `/portty`, `CARGO_TARGET_DIR` → `/target`). That variable replaces the flags
  the Tauri CLI passes, so the script carries Tauri's link flags over (or your
  own `RUSTFLAGS`, if set). Always build releases with `pnpm tauri ...`: the
  Gradle build fails a release whose library still names your home folder or
  checkout (`npx tauri` or `cargo tauri` would skip the script). The first
  release build after changing these flags rebuilds every crate. Cargo's
  `trim-paths` can replace this once it is stable.

Check a release build (NDK tools are under
`$NDK_HOME/toolchains/llvm/prebuilt/<host>/bin`):

```sh
unzip -o -d /tmp/so app-arm64-release.apk 'lib/*'
llvm-readelf -S -l /tmp/so/lib/arm64-v8a/libportty_app_lib.so  # no .symtab, LOAD align 0x4000
llvm-readelf -n /tmp/so/lib/arm64-v8a/libportty_app_lib.so     # NDK r30 (16248370), no beta
grep -a -c "$(whoami)" /tmp/so/lib/arm64-v8a/libportty_app_lib.so  # expect 0
"$ANDROID_HOME/build-tools/36.1.0/zipalign" -c -P 16 4 app-arm64-release.apk
unzip -l app-arm64-release.aab | grep debugsymbols
```
